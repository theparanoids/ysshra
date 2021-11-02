package regular

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"path"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.vzbuilders.com/peng/sshra-oss/csr"
)

func newSSHPublicKey(t *testing.T) (*rsa.PrivateKey, ssh.PublicKey) {
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

func TestHandler_challengePubKey(t *testing.T) {
	tests := []struct {
		name       string
		GetHandler func(t *testing.T, logName string) Handler
		logName    string
		wantErr    bool
	}{
		{
			name: "happy path",
			GetHandler: func(t *testing.T, logName string) Handler {
				ag := agent.NewKeyring()
				// generate priv/pub key
				priv, pub := newSSHPublicKey(t)
				addedKey := agent.AddedKey{PrivateKey: priv}
				if err := ag.Add(addedKey); err != nil {
					t.Fatal(err)
				}
				// generate public key file
				tmpDir := t.TempDir()
				if err := ioutil.WriteFile(path.Join(tmpDir, logName), pub.Marshal(), 0400); err != nil {
					t.Fatal(err)
				}
				return Handler{
					agent:         ag,
					pubKeyDirPath: tmpDir,
				}
			},
			logName: "dummy",
		},
		{
			name: "pubKey mismatch (cannot sign the challenge)",
			GetHandler: func(t *testing.T, logName string) Handler {
				ag := agent.NewKeyring()
				// generate priv/pub key
				priv, _ := newSSHPublicKey(t)
				addedKey := agent.AddedKey{PrivateKey: priv}
				if err := ag.Add(addedKey); err != nil {
					t.Fatal(err)
				}
				// generate a mis-matched public key file
				tmpDir := t.TempDir()
				_, mismatchedPub := newSSHPublicKey(t)
				if err := ioutil.WriteFile(path.Join(tmpDir, logName), mismatchedPub.Marshal(), 0400); err != nil {
					t.Fatal(err)
				}
				return Handler{
					agent:         ag,
					pubKeyDirPath: tmpDir,
				}
			},
			logName: "dummy",
			wantErr: true,
		},
		{
			name: "missing pubKey File",
			GetHandler: func(t *testing.T, logName string) Handler {
				ag := agent.NewKeyring()
				// generate priv/pub key
				priv, _ := newSSHPublicKey(t)
				addedKey := agent.AddedKey{PrivateKey: priv}
				if err := ag.Add(addedKey); err != nil {
					t.Fatal(err)
				}
				return Handler{
					agent:         ag,
					pubKeyDirPath: "invalidPath",
				}
			},
			logName: "dummy",
			wantErr: true,
		},
		{
			name: "invalid public key",
			GetHandler: func(t *testing.T, logName string) Handler {
				ag := agent.NewKeyring()
				// generate priv/pub key
				priv, _ := newSSHPublicKey(t)
				addedKey := agent.AddedKey{PrivateKey: priv}
				if err := ag.Add(addedKey); err != nil {
					t.Fatal(err)
				}
				// generate a mis-matched public key file
				tmpDir := t.TempDir()
				if err := ioutil.WriteFile(path.Join(tmpDir, logName), []byte("invalidPubKey"), 0400); err != nil {
					t.Fatal(err)
				}
				return Handler{
					agent:         ag,
					pubKeyDirPath: tmpDir,
				}
			},
			logName: "dummy",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.GetHandler(t, tt.logName)
			if err := h.challengePubKey(&csr.ReqParam{LogName: tt.logName}); (err != nil) != tt.wantErr {
				t.Errorf("challengePubKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
