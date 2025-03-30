// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_f9_verify

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	yconfig "github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/modules"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// Name is a unique name to identify an authentication module.
	Name = "f9_verify"

	modHexMap = "cbdefghijklnrtuv"
	hexMap    = "0123456789abcdef"
)

type authn struct {
	f9CertsDir string
	agent      yubiagent.YubiAgent
}

// New returns an authentication module.
func New(ag agent.Agent, c map[string]interface{}) (modules.AuthnModule, error) {
	conf := &config{}
	if err := yconfig.DecodeModuleConfig(c, conf); err != nil {
		return nil, fmt.Errorf("failed to initilaize module %q, %v", Name, err)
	}

	yubiAgent, ok := ag.(yubiagent.YubiAgent)
	if !ok {
		return nil, fmt.Errorf("yubiagent is the only supported agent in module %q", Name)
	}
	return &authn{
		f9CertsDir: conf.F9CertsDir,
		agent:      yubiAgent,
	}, nil
}

// Authenticate checks if f9 cert is modified or imported.
func (a *authn) Authenticate(_ *csr.ReqParam) error {
	f9Cert, err := a.agent.ReadSlot("f9")
	if err != nil {
		return fmt.Errorf(`failed to read slot f9, %v`, err)
	}

	if err := VerifyF9Cert(a.f9CertsDir, f9Cert); err != nil {
		return fmt.Errorf(`failed to verify f9 attestation cert, %v"`, err)
	}
	return nil
}

// VerifyF9Cert will ensure that the user is using a Yubikey that was provisioned to him or her,
// rather than just any Yubikey.
func VerifyF9Cert(f9CertDirPath string, f9Cert *x509.Certificate) error {
	const (
		prefix = "0"
		suffix = ".pem"
	)
	f9Serial, err := yubiattest.ModHex(f9Cert)
	if err != nil {
		return err
	}
	f9SerialNum, err := getAttestationSerialNum([]byte(f9Serial))
	if err != nil {
		return fmt.Errorf("couldn't get serial from yubikey f9 slot: serial=%s", f9Serial)
	}

	f9SerialNumStr := strconv.FormatUint(f9SerialNum, 10)

	// Since the serial number keeps incrementing when new Yubikeys are manufactured,
	// the serial number once can be fitted in 7 decimal digits,
	// but now it needs 8 decimal digits.
	// For those old yubikeys with serial numbers of 7 decimal digits,
	// the file name of the corresponding f9 cert is prepended with a `0`.
	if len(f9SerialNumStr) < 8 {
		f9SerialNumStr = prefix + f9SerialNumStr
	}

	// Get the attestation cert provided by yubico in the configured path.
	certPath := path.Join(f9CertDirPath, f9SerialNumStr+suffix)
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("unable to read attestation cert file: serial=%s, path=%s", f9Serial, certPath)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("couldn't decode f9 cert: serial=%s, path=%s", f9Serial, certPath)
	}
	if !bytes.Equal(block.Bytes, f9Cert.Raw) {
		return fmt.Errorf("attestation cert mismatch: serial=%s, path=%s", f9Serial, certPath)
	}
	return nil
}

// getAttestationSerialNum gets the serial number of attestation cert in Decimal format.
// Ref: https://developers.yubico.com/OTP/Modhex_Converter.html
func getAttestationSerialNum(modHex []byte) (uint64, error) {
	var hexString string
	for _, val := range modHex {
		b := bytes.IndexByte([]byte(modHexMap), val)
		if b == -1 {
			b = 0
		}
		hexString += fmt.Sprintf("%c", hexMap[b])
	}
	return strconv.ParseUint(hexString, 16, 64)
}
