package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testSSHCertificate(t *testing.T, prins ...string) (*ssh.Certificate, ssh.PublicKey, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Error(err)
	}
	crt := &ssh.Certificate{
		KeyId:           "keyID",
		CertType:        ssh.UserCert,
		ValidPrincipals: prins,
		Key:             pub,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Unix()) + 1000,
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Error(err)
	}
	if err := crt.SignCert(rand.Reader, signer); err != nil {
		t.Error(err)
	}
	return crt, pub, priv
}

func TestAgentKey_NewSSHAgentKeyWithOpt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		agent   agent.Agent
		opt     KeyOpt
		wantErr bool
	}{
		{
			name:  "happy path",
			opt:   DefaultKeyOpt,
			agent: agent.NewKeyring(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentKey, err := NewSSHAgentKeyWithOpt(tt.agent, tt.opt)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSSHAgentKeyWithOpt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			pub := agentKey.PublicKey()
			wantKeys := []agent.Key{
				{
					Format:  pub.Type(),
					Blob:    pub.Marshal(),
					Comment: DefaultKeyOpt.PrivateKeyLabel,
				},
			}
			gotKeys, err := ListKeys(tt.agent, func(key *agent.Key) bool { return true })
			if !reflect.DeepEqual(gotKeys, wantKeys) {
				t.Errorf("ListKeys() got = %v, want %v", gotKeys, wantKeys)
			}
		})
	}
}

func TestAgentKey_AddCertsToAgent(t *testing.T) {
	t.Parallel()

	cert, pub, priv := testSSHCertificate(t, "example")
	tests := []struct {
		name     string
		agentKey func(t *testing.T) *AgentKey
		wantKeys []agent.Key
		wantErr  bool
	}{
		{
			name: "happy path",
			agentKey: func(t *testing.T) *AgentKey {
				a := agent.NewKeyring()
				agentKey, err := NewSSHAgentKey(a)
				if err != nil {
					t.Fatal(err)
				}
				err = a.RemoveAll()
				if err != nil {
					t.Fatal(err)
				}
				addedKey := agent.AddedKey{
					PrivateKey:   priv,
					Comment:      "comment",
					LifetimeSecs: 1000,
				}
				err = a.Add(addedKey)
				agentKey.addedKey = addedKey
				if err != nil {
					t.Fatal(err)
				}
				return agentKey
			},
			wantKeys: []agent.Key{
				{
					Format:  pub.Type(),
					Blob:    pub.Marshal(),
					Comment: "comment",
				},
				{
					Format:  cert.Type(),
					Blob:    cert.Marshal(),
					Comment: "certificate",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.agentKey(t)
			if err := a.AddCertsToAgent([]ssh.PublicKey{cert}, []string{"comment"}); (err != nil) != tt.wantErr {
				t.Errorf("AddCertsToAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			gotKeys, _ := ListKeys(a.agent, func(key *agent.Key) bool { return true })
			if !reflect.DeepEqual(gotKeys, tt.wantKeys) {
				t.Errorf("ListKeys() got = %v, want %v", gotKeys, tt.wantKeys)
			}
		})
	}
}
