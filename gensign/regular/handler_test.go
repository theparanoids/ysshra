// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package regular

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"path"
	"testing"

	"github.com/theparanoids/ysshura/common"
	"github.com/theparanoids/ysshura/csr"
	"github.com/theparanoids/ysshura/csr/transid"
	"github.com/theparanoids/ysshura/message"
	"github.com/theparanoids/ysshura/sshutils/version"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newSSHKeyPair(t *testing.T) (*rsa.PrivateKey, ssh.PublicKey) {
	t.Helper()

	const (
		bit = 2048
	)
	priv, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func newSSHKeyPairInAgent(t *testing.T) (*rsa.PrivateKey, ssh.PublicKey, agent.Agent) {
	t.Helper()

	priv, pub := newSSHKeyPair(t)
	ag := agent.NewKeyring()
	addedKey := agent.AddedKey{PrivateKey: priv}
	if err := ag.Add(addedKey); err != nil {
		t.Fatal(err)
	}
	return priv, pub, ag
}

func writePubKeyFile(t *testing.T, logName string, pubBytes []byte) string {
	t.Helper()

	tmpDir := t.TempDir()
	if err := ioutil.WriteFile(path.Join(tmpDir, logName), pubBytes, 0400); err != nil {
		t.Fatal(err)
	}
	return tmpDir
}

func TestHandler_Authenticate(t *testing.T) {
	t.Parallel()

	goodParam := &csr.ReqParam{
		NamespacePolicy:  common.NoNamespace,
		HandlerName:      "Regular",
		ClientIP:         "1.2.3.4",
		LogName:          "dummy",
		ReqUser:          "dummy",
		ReqHost:          "dummy.com",
		TransID:          transid.Generate(),
		SSHClientVersion: version.New(8, 1),
		Attrs: &message.Attributes{
			Username:         "dummy",
			Hostname:         "dummy.com",
			SSHClientVersion: "8.1",
			HardKey:          false,
			Touch2SSH:        false,
			TouchlessSudo:    nil,
		},
	}

	tests := map[string]struct {
		params     *csr.ReqParam
		GetHandler func(t *testing.T) Handler
		wantErr    bool
	}{
		"happy path": {
			params: goodParam,
			GetHandler: func(t *testing.T) Handler {
				_, pub, ag := newSSHKeyPairInAgent(t)
				tmpDir := writePubKeyFile(t, "dummy", ssh.MarshalAuthorizedKey(pub))
				return Handler{
					agent: ag,
					conf:  &conf{PubKeyDir: tmpDir},
				}
			},
		},
		"nil param": {
			GetHandler: func(t *testing.T) Handler {
				_, pub, ag := newSSHKeyPairInAgent(t)
				tmpDir := writePubKeyFile(t, "dummy", ssh.MarshalAuthorizedKey(pub))
				return Handler{
					agent: ag,
					conf:  &conf{PubKeyDir: tmpDir},
				}
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := test.GetHandler(t)
			if err := h.Authenticate(test.params); (err != nil) != test.wantErr {
				t.Errorf("challengePubKey() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestHandler_challengePubKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		GetHandler func(t *testing.T, logName string) Handler
		logName    string
		wantErr    bool
	}{
		{
			name: "happy path",
			GetHandler: func(t *testing.T, logName string) Handler {
				_, pub, ag := newSSHKeyPairInAgent(t)
				tmpDir := writePubKeyFile(t, logName, ssh.MarshalAuthorizedKey(pub))
				return Handler{
					agent: ag,
					conf:  &conf{PubKeyDir: tmpDir},
				}
			},
			logName: "dummy",
		},
		{
			name: "pubKey mismatch (cannot sign the challenge)",
			GetHandler: func(t *testing.T, logName string) Handler {
				_, _, ag := newSSHKeyPairInAgent(t)
				_, mismatchedPub := newSSHKeyPair(t)
				tmpDir := writePubKeyFile(t, logName, ssh.MarshalAuthorizedKey(mismatchedPub))
				return Handler{
					agent: ag,
					conf:  &conf{PubKeyDir: tmpDir},
				}
			},
			logName: "dummy",
			wantErr: true,
		},
		{
			name: "missing pubKey File",
			GetHandler: func(t *testing.T, logName string) Handler {
				_, _, ag := newSSHKeyPairInAgent(t)
				return Handler{
					agent: ag,
					conf:  &conf{PubKeyDir: "invalidPath"},
				}
			},
			logName: "dummy",
			wantErr: true,
		},
		{
			name: "invalid public key",
			GetHandler: func(t *testing.T, logName string) Handler {
				_, _, ag := newSSHKeyPairInAgent(t)
				tmpDir := writePubKeyFile(t, logName, []byte("invalidPubKey"))
				return Handler{
					agent: ag,
					conf:  &conf{PubKeyDir: tmpDir},
				}
			},
			logName: "dummy",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := tt.GetHandler(t, tt.logName)
			if err := h.challengePubKey(&csr.ReqParam{LogName: tt.logName}); (err != nil) != tt.wantErr {
				t.Errorf("challengePubKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
