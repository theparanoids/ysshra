// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr_smartcard_hardkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/crypki"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/message"
	"github.com/theparanoids/ysshra/modules"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		agent   func(t *testing.T) (sshagent.Agent, map[string]interface{})
		want    *generator
		wantErr bool
	}{
		{
			name: "happy path",
			agent: func(t *testing.T) (sshagent.Agent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)

				happyPathAttestCert := &x509.Certificate{
					PublicKey: &rsa.PublicKey{},
					Extensions: []pkix.Extension{
						{
							Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
							Value: []byte{0, byte(keyid.NeverTouch)},
						},
					},
				}
				yubicoAgent.EXPECT().AttestSlot("9a").Return(happyPathAttestCert, nil).Times(1)
				return yubicoAgent, map[string]interface{}{
					"touch_policy":      1,
					"principals_tpl":    "<logname>",
					"slot":              "9a",
					"cert_validity_sec": 3600,
				}
			},
			want: &generator{
				c: &conf{
					TouchPolicy:     1,
					PrincipalsTpl:   "<logname>",
					Slot:            "9a",
					CertValiditySec: 3600,
				},
				opt: &modules.CSROption{},
			},
		},
		{
			name: "failed to extract config",
			agent: func(t *testing.T) (sshagent.Agent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				return yubicoAgent, map[string]interface{}{
					"touch_policy": "invalid",
				}
			},
			wantErr: true,
		},
		{
			name: "invalid key agent",
			agent: func(t *testing.T) (sshagent.Agent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				agent := sshagent.NewKeyring()
				return agent, map[string]interface{}{
					"touch_policy":      1,
					"principals":        "<logname>",
					"slot":              "9a",
					"cert_validity_sec": 3600,
				}
			},
			wantErr: true,
		},
		{
			name: "failed to fetch attest certs",
			agent: func(t *testing.T) (sshagent.Agent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().AttestSlot("9a").Return(nil, errors.New("invalid attestation")).Times(1)
				return yubicoAgent, map[string]interface{}{
					"touch_policy":      1,
					"principals":        "<logname>",
					"slot":              "9a",
					"cert_validity_sec": 3600,
				}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag, c := tt.agent(t)
			got, err := New(ag, c, &modules.CSROption{})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			gotMod, ok := got.(*generator)
			if !ok {
				t.Errorf("the generator is not the correct type")
			}
			tt.want.slotAgent = gotMod.slotAgent
			if !reflect.DeepEqual(gotMod, tt.want) {
				t.Errorf("New() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generator_Generate(t *testing.T) {
	tests := []struct {
		name    string
		agent   func(t *testing.T) *yubiagent.SlotAgent
		c       *conf
		opt     *modules.CSROption
		param   *csr.ReqParam
		want    func(t *testing.T) *proto.SSHCertificateSigningRequest
		wantErr bool
	}{
		{
			name: "happy path",
			agent: func(t *testing.T) *yubiagent.SlotAgent {
				priv, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Error(err)
				}
				pub, err := ssh.NewPublicKey(&priv.PublicKey)
				if err != nil {
					t.Error(err)
				}
				return yubiagent.NewSlotAgentWithAttrs(nil, "9a", pub, nil, keyid.DefaultTouch)
			},
			c: &conf{
				IsFirefighter:   true,
				TouchPolicy:     1,
				PrincipalsTpl:   "<logname>",
				Slot:            "9a",
				CertValiditySec: 86400,
			},
			opt: &modules.CSROption{
				KeyIdentifiers: map[x509.PublicKeyAlgorithm]string{
					x509.RSA: "rsa-key-identifier",
				},
				KeyIDVersion: 1,
			},
			param: &csr.ReqParam{
				LogName: "testuser",
				Attrs: &message.Attributes{
					CAPubKeyAlgo: x509.RSA,
				},
				TransID:  "12345",
				ReqUser:  "ReqUser",
				ClientIP: "1.2.3.4",
				ReqHost:  "example-host.com",
			},
			want: func(t *testing.T) *proto.SSHCertificateSigningRequest {
				kid := &keyid.KeyID{
					Principals:    []string{"testuser"},
					TransID:       "12345",
					ReqUser:       "ReqUser",
					ReqIP:         "1.2.3.4",
					ReqHost:       "example-host.com",
					Version:       1,
					IsFirefighter: true,
					IsHWKey:       true,
					IsHeadless:    false,
					IsNonce:       false,
					Usage:         keyid.AllUsage,
					TouchPolicy:   keyid.NeverTouch,
				}
				kidMarshalled, err := kid.Marshal()
				if err != nil {
					t.Error(err)
				}
				return &proto.SSHCertificateSigningRequest{
					KeyMeta:    &proto.KeyMeta{Identifier: "rsa-key-identifier"},
					Extensions: crypki.GetDefaultExtension(),
					Validity:   86400,
					Principals: []string{"testuser"},
					KeyId:      kidMarshalled,
				}
			},
		},
		{
			name: "failed to lookup key identifier",
			agent: func(t *testing.T) *yubiagent.SlotAgent {
				priv, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Error(err)
				}
				pub, err := ssh.NewPublicKey(&priv.PublicKey)
				if err != nil {
					t.Error(err)
				}
				return yubiagent.NewSlotAgentWithAttrs(nil, "9a", pub, nil, keyid.DefaultTouch)
			},
			c: &conf{},
			opt: &modules.CSROption{
				KeyIdentifiers: map[x509.PublicKeyAlgorithm]string{},
				KeyIDVersion:   1,
			},
			param: &csr.ReqParam{
				Attrs: &message.Attributes{
					CAPubKeyAlgo: x509.RSA,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &generator{
				slotAgent: tt.agent(t),
				c:         tt.c,
				opt:       tt.opt,
			}
			got, err := g.Generate(tt.param)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(got) != 1 || len(got[0].CSRs()) != 1 {
				t.Errorf("want a csr returned in the agent key, got %v", got)
			}
			gotCSR := got[0].CSRs()[0]
			wantCSR := tt.want(t)
			wantCSR.PublicKey = gotCSR.PublicKey // We don't check public key.
			if !reflect.DeepEqual(gotCSR, wantCSR) {
				t.Errorf("Generate() got CSR = %v, want %v", gotCSR, wantCSR)
			}
		})
	}
}
