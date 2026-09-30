// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_slot_serial

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/agent/yubiagent/mock"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/keyid"
)

func testSignX509Cert(unsignedCert, caCert *x509.Certificate, pubKey *rsa.PublicKey,
	caPrivKey *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, unsignedCert, caCert, pubKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pem := pem.EncodeToMemory(&b)

	return cert, pem, nil
}

func testSelfSignX509Cert() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	return testSelfSignX509CertWithBits(2048)
}

func testSelfSignX509CertWithBits(bits int) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	var unsignedCert = &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		PublicKeyAlgorithm: x509.ECDSA,
		IsCA:               true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, pem, err := testSignX509Cert(unsignedCert, unsignedCert, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pem, priv, nil
}

func testGenSignX509Cert(caCert *x509.Certificate, caKey *rsa.PrivateKey,
	priv *rsa.PrivateKey, yubikeyHexDecimal []byte) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	if priv == nil {
		var err error
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	var unsignedCert = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageCRLSign,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7},
				Value: yubikeyHexDecimal,
			},
		},
	}

	cert, pem, err := testSignX509Cert(unsignedCert, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pem, priv, err
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		agent   func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{})
		want    *authn
		wantErr bool
	}{
		{
			name: "happy path",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := mock.NewMockYubiAgent(mockCtrl)

				happyPathAttestCert := &x509.Certificate{
					PublicKey: &rsa.PublicKey{},
					Extensions: []pkix.Extension{
						{
							Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
							Value: []byte{0, byte(keyid.NeverTouch)},
						},
					},
				}
				yubicoAgent.EXPECT().AttestSlot("9a").
					Return(happyPathAttestCert, nil).Times(1)

				return yubicoAgent, map[string]interface{}{
					"slot":             "9a",
					"yubikey_mappings": "/path/to/yubikey/mappings",
				}
			},
			want: &authn{
				yubikeyMappings: "/path/to/yubikey/mappings",
			},
		},
		{
			name: "failed to create slot agent",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := mock.NewMockYubiAgent(mockCtrl)

				yubicoAgent.EXPECT().AttestSlot("9a").
					Return(nil, errors.New("some agent error")).Times(1)

				return yubicoAgent, map[string]interface{}{
					"slot":             "9a",
					"yubikey_mappings": "/path/to/yubikey/mappings",
				}
			},
			wantErr: true,
		},
		{
			name: "invalid config",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := mock.NewMockYubiAgent(mockCtrl)

				return yubicoAgent, map[string]interface{}{
					"slot": 123,
				}
			},
			wantErr: true,
		},
		{
			name: "invalid agent",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				return nil, map[string]interface{}{
					"slot": 123,
				}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag, c := tt.agent(t)
			got, err := New(ag, c)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			gotMod, ok := got.(*authn)
			if !ok {
				t.Errorf("the module is not the correct authn")
			}
			gotMod.slot = nil // We don't need to check slot agent in this unit test.
			if !reflect.DeepEqual(gotMod, tt.want) {
				t.Errorf("New() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authn_Authenticate(t *testing.T) {
	tests := []struct {
		name        string
		agent       func(t *testing.T) *yubiagent.Slot
		mappingPath string
		reqParam    *csr.ReqParam
		wantErr     bool
	}{
		{
			name: "happy path",
			agent: func(t *testing.T) *yubiagent.Slot {
				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				// "02:04:04:03:02:01" is the HEX Decimal encoding of the yubikey serial number.
				// The first byte (`02`) indicates that the type is integer.
				// The second byte (`04`) denotes the number of bytes of the value.
				// The rest of the bytes (`04`, `03`, `02`, `01`) can be converted to
				// modhex `cfcecdcb` and decimal `67305985`.
				cert, _, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{02, 04, 04, 03, 02, 01})
				if err != nil {
					t.Fatal(err)
				}
				agent := yubiagent.NewSlotWithAttrs(nil, "9a", nil, cert, 0)
				return agent
			},
			reqParam: &csr.ReqParam{
				LogName: "test_user1",
			},
			mappingPath: "./testdata/yubikey_mappings",
		},
		{
			name: "no user found in the mapping",
			agent: func(t *testing.T) *yubiagent.Slot {
				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				cert, _, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{00, 00, 00, 00, 00, 00}) // an invalid decimal
				if err != nil {
					t.Fatal(err)
				}
				agent := yubiagent.NewSlotWithAttrs(nil, "9a", nil, cert, 0)
				return agent
			},
			reqParam: &csr.ReqParam{
				LogName: "test_user1",
			},
			mappingPath: "./testdata/yubikey_mappings",
			wantErr:     true,
		},
		{
			name: "failed to read mapping file",
			agent: func(t *testing.T) *yubiagent.Slot {
				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				cert, _, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{00, 00, 00, 00, 00, 00})
				if err != nil {
					t.Fatal(err)
				}
				agent := yubiagent.NewSlotWithAttrs(nil, "9a", nil, cert, 0)
				return agent
			},
			reqParam: &csr.ReqParam{
				LogName: "test_user1",
			},
			mappingPath: "./testdata/invalid-path",
			wantErr:     true,
		},
		{
			name: "invalid user",
			agent: func(t *testing.T) *yubiagent.Slot {
				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				// "02:04:04:03:02:01" is the HEX Decimal encoding of the yubikey serial number.
				// The first byte (`02`) indicates that the type is integer.
				// The second byte (`04`) denotes the number of bytes of the value.
				// The rest of the bytes (`04`, `03`, `02`, `01`) can be converted to
				// modhex `cfcecdcb` and decimal `67305985`.
				cert, _, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{02, 04, 04, 03, 02, 01})
				if err != nil {
					t.Fatal(err)
				}
				agent := yubiagent.NewSlotWithAttrs(nil, "9a", nil, cert, 0)
				return agent
			},
			reqParam: &csr.ReqParam{
				LogName: "invalid user",
			},
			mappingPath: "./testdata/invalid-path",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := tt.agent(t)
			a := &authn{
				slot:            agent,
				yubikeyMappings: tt.mappingPath,
			}
			if err := a.Authenticate(tt.reqParam); (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
