// Copyright 2023 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
	"github.com/theparanoids/ysshra/csr/transid"
	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/sshutils/key"

	"golang.org/x/crypto/ssh"
)

const (
	hostPrivKeyPath = "./hostkey"
	hostPubKeyPath  = "./hostkey.pub"
	hostCertPath    = "./hostkey-cert.pub"
)

var (
	cfg          string
	principals   []string
	validityDays uint64
	keyType      string
	reqUser      string
	keyAlgorithm key.PublicKeyAlgo
)

func parseFlags() {
	var prins string
	flag.StringVar(&cfg, "config", "", "CA key configuration file")
	flag.Uint64Var(&validityDays, "days", 730, "validity period in days")
	flag.StringVar(&prins, "prins", "", "principal list")
	flag.StringVar(&keyType, "keyType", "", "key algorithm type to generate key/cert pair (supported options: RSA2048, ECCP256, ECCP384)")
	flag.StringVar(&reqUser, "reqUser", "devops", "user to request the certificate")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if cfg == "" {
		log.Fatal("no CA key configuration file specified")
	}

	var err error
	keyAlgorithm, err = key.GetSSHKeyAlgo(keyType)
	if err != nil {
		log.Printf("warning: %v", err)
	}

	principals = strings.Split(prins, ",")
}

func constructUnsignedSSHCert(pub ssh.PublicKey) (*ssh.Certificate, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %v", err)
	}

	keyID := keyid.KeyID{
		Version:       1,
		Principals:    principals,
		TransID:       transid.Generate(),
		TouchPolicy:   1,
		IsHWKey:       false,
		IsHeadless:    true,
		IsFirefighter: false,
		ReqUser:       reqUser,
		ReqHost:       hostname,
		ReqIP:         getLocalIP(),
	}
	keyIDString, err := keyID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keyID string: %v", err)
	}

	return &ssh.Certificate{
		KeyId:           keyIDString,
		CertType:        ssh.HostCert,
		ValidPrincipals: principals,
		Key:             pub,
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()), // backdate to address possible clock drift,
		ValidBefore:     uint64(time.Now().Add(time.Hour * 24 * time.Duration(validityDays)).Unix()),
	}, nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func encodePrivateKey(privKey crypto.PrivateKey) ([]byte, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privBytes,
	}), nil
}

func main() {
	parseFlags()

	cfgData, err := os.ReadFile(cfg)
	if err != nil {
		log.Fatal(err)
	}
	cc := &crypki.CAConfig{}
	if err := json.Unmarshal(cfgData, cc); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requireX509CACert := map[string]bool{
		cc.Identifier: false,
	}

	requestChan := make(chan scheduler.Request)
	p := &scheduler.Pool{Name: cc.Identifier, PoolSize: 2, FeatureEnabled: true, PKCS11Timeout: config.DefaultPKCS11Timeout * time.Second}
	go scheduler.CollectRequest(ctx, requestChan, p)

	signer, err := pkcs11.NewCertSign(ctx, cc.PKCS11ModulePath, []config.KeyConfig{{
		Identifier:      cc.Identifier,
		SlotNumber:      uint(cc.SlotNumber),
		UserPinPath:     cc.UserPinPath,
		KeyLabel:        cc.KeyLabel,
		KeyType:         x509.PublicKeyAlgorithm(cc.KeyType),
		SignatureAlgo:   x509.SignatureAlgorithm(cc.SignatureAlgo),
		SessionPoolSize: 2,
	}}, requireX509CACert, "", nil, nil, config.DefaultPKCS11Timeout) // Hostname, IPs and URI should not be needed for ssh cert signing.

	if err != nil {
		log.Fatalf("unable to initialize cert signer: %v", err)
	}

	priv, pub, err := key.GenerateKeyPair(keyAlgorithm)
	if err != nil {
		log.Fatal(err)
	}

	privPem, err := encodePrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := constructUnsignedSSHCert(pub)
	if err != nil {
		log.Fatal(err)
	}

	data, err := signer.SignSSHCert(ctx, requestChan, cert, cc.Identifier, proto.Priority_Unspecified_priority)
	if err != nil {
		log.Fatalf("falied to sign ssh cert: %v", err)
	}

	if err := os.WriteFile(hostPrivKeyPath, privPem, 0400); err != nil {
		log.Printf("successfully generated a private key, but unable to write to file %s: %v", hostPrivKeyPath, err)
	} else {
		log.Printf("the generated priv key was written to %s", hostPrivKeyPath)
	}

	if err := os.WriteFile(hostPubKeyPath, ssh.MarshalAuthorizedKey(pub), 0444); err != nil {
		log.Printf("successfully generated a public key, but unable to write to file %s: %v", hostPubKeyPath, err)
	} else {
		log.Printf("the generated public key was written to %s", hostPubKeyPath)
	}

	if err := os.WriteFile(hostCertPath, data, 0444); err != nil {
		log.Printf("sucessfully generated a cert, but unable to write to file %s: %v", hostCertPath, err)
	} else {
		log.Printf("the generated cert was written to %s", hostCertPath)
	}
}
