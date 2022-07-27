// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package shimagent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/theparanoids/ysshra/sshutils/key"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
	ag "golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/nettest"
)

// testServer create a fake server for unit tests
func testServer(t *testing.T, noUpstream bool) ShimAgent {
	keyring := ag.NewKeyring()
	listener, err := nettest.NewLocalListener("unix")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		err = ag.ServeAgent(keyring, conn)
		if err != nil {
			t.Fatal(err)
		}
	}()
	s, err := New(Option{
		Address:    listener.Addr().String(),
		NoUpstream: noUpstream,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// createPublicKey create public and privaty key pairs for unit test
func createPublicKey() (*rsa.PrivateKey, ssh.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func TestServer_filter(t *testing.T) {
	t.Parallel()

	now := time.Now()
	priv, pub, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	certExpired := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       "keyid",
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(-time.Minute).Unix()),
	}
	if err := certExpired.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	cert := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       "keyid",
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Minute).Unix()),
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	privOrphan, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signerOrphan, err := ssh.NewSignerFromKey(privOrphan)
	if err != nil {
		t.Fatal(err)
	}

	certOrphan := &ssh.Certificate{
		Key:         signerOrphan.PublicKey(),
		KeyId:       "keyid",
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certOrphan.SignCert(rand.Reader, signerOrphan); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		setup     func(s ShimAgent) error
		wantCerts map[hashcode]*certificate
		wantKeys  []*ag.Key
		wantErr   bool
	}{
		{
			name: "orphan cert and expired certs should be removed",
			setup: func(s ShimAgent) error {
				if err := s.Add(ag.AddedKey{PrivateKey: priv}); err != nil {
					return err
				}

				if err := s.Add(ag.AddedKey{PrivateKey: priv, Certificate: cert, Comment: "regular"}); err != nil {
					return err
				}

				if err := s.Add(ag.AddedKey{PrivateKey: priv, Certificate: certExpired, Comment: "expired"}); err != nil {
					return err
				}

				if err := s.AddHardCert(certExpired, "expired"); err != nil {
					return err
				}

				s.(*Server).certs[hash(certOrphan.Marshal())] = &certificate{
					Certificate: certOrphan,
					Blob:        certOrphan.Marshal(),
					Comment:     "orphan",
				}
				return nil
			},
			wantCerts: map[hashcode]*certificate{},
			wantKeys: []*ag.Key{
				{
					Format: pub.Type(),
					Blob:   pub.Marshal(),
				},
				{
					Format:  cert.Type(),
					Blob:    cert.Marshal(),
					Comment: "regular",
				},
			},
		},
		{
			name: "not remove orphan certs when the underlying agent return empty list",
			setup: func(s ShimAgent) error {
				s.(*Server).certs[hash(certOrphan.Marshal())] = &certificate{
					Certificate: certOrphan,
					Blob:        certOrphan.Marshal(),
					Comment:     "orphan",
				}
				return nil
			},
			wantCerts: map[hashcode]*certificate{
				hash(ssh.PublicKey(certOrphan).Marshal()): {
					Certificate: certOrphan,
					Blob:        ssh.PublicKey(certOrphan).Marshal(),
					Comment:     "orphan",
				},
			},
			wantKeys: []*ag.Key{},
		},
	}

	compareCertificate := cmp.Comparer(func(x, y *ssh.Certificate) bool {
		return x == y
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testServer(t, true)
			err := tt.setup(s)
			if err != nil {
				t.Fatal(err)
			}

			gotCerts, gotKeys, err := s.(*Server).filter()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error, got: %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if !cmp.Equal(gotCerts, s.(*Server).certs, compareCertificate) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v", cmp.Diff(gotCerts, s.(*Server).certs, compareCertificate))
			}
			if !cmp.Equal(gotCerts, tt.wantCerts, compareCertificate) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v", cmp.Diff(gotCerts, tt.wantCerts, compareCertificate))
			}

			keys, err := s.(*Server).agent.List()
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(gotKeys, keys) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v", cmp.Diff(gotKeys, keys))
			}
			if !cmp.Equal(gotKeys, tt.wantKeys) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v", cmp.Diff(gotKeys, tt.wantKeys))
			}
		})
	}
}

func TestListWithKeyIDv1(t *testing.T) {
	// Order:
	// 1. Touchless in-agent cert (first)
	// 2. Touchless cert
	// 3. Cached Touch cert
	// 4. Always Touch cert
	// 5. Key
	// 6. Touchless in-agent with CriticalOptions cert
	// 7. Touchless with CriticalOptions cert
	// 8. Cached Touch with CriticalOptions cert
	// 9. Always Touch with CriticalOptions cert

	t.Parallel()

	now := time.Now()

	priv, keyInAgent, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Create Always Touch cert.
	certAlwaysTouch := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certAlwaysTouch.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Always Touch cert with CriticalOptions.
	certAlwaysTouchWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certAlwaysTouchWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch cert.
	certTouchless := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certTouchless.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch in-agent cert.
	certTouchlessInAgent := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":true,"isHWKey":false,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certTouchlessInAgent.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Cached Touch cert.
	certCachedTouch := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certCachedTouch.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch cert with CriticalOptions.
	certTouchlessWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certTouchlessWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Cached Touch cert with CriticalOptions.
	certCachedTouchWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certCachedTouchWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch in-agent cert with CriticalOptions.
	certTouchlessInAgentWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":true,"isHWKey":false,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certTouchlessInAgentWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		NoUpstream                      bool
		TouchlessInAgent                bool
		Touchless                       bool
		CachedTouch                     bool
		AlwaysTouch                     bool
		TouchlessInAgentCriticalOptions bool
		TouchlessCriticalOptions        bool
		CachedTouchCriticalOptions      bool
		AlwaysTouchCriticalOptions      bool
		want                            []*ag.Key
	}{
		"Key and Certs": {
			TouchlessInAgent: true,
			Touchless:        true,
			CachedTouch:      true,
			AlwaysTouch:      true,
			want: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal(), Comment: "InAgentKey"},
				{Format: certAlwaysTouch.Type(), Blob: certAlwaysTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouch"},
				{Format: certCachedTouch.Type(), Blob: certCachedTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouch"},
				{Format: certTouchlessInAgent.Type(), Blob: certTouchlessInAgent.Marshal(), Comment: "TouchlessInAgentSSH-a7af667d-certTouchlessInAgent"},
				{Format: certTouchless.Type(), Blob: certTouchless.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchless"},
			},
		},
		"Key and Certs with no-upstream": {
			NoUpstream:       true,
			TouchlessInAgent: true,
			Touchless:        true,
			CachedTouch:      true,
			AlwaysTouch:      true,
			want: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal(), Comment: "InAgentKey"},
				{Format: certAlwaysTouch.Type(), Blob: certAlwaysTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouch"},
				{Format: certCachedTouch.Type(), Blob: certCachedTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouch"},
				{Format: certTouchless.Type(), Blob: certTouchless.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchless"},
			},
		},
		"All": {
			TouchlessInAgent:                true,
			Touchless:                       true,
			CachedTouch:                     true,
			AlwaysTouch:                     true,
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal(), Comment: "InAgentKey"},
				{Format: certAlwaysTouch.Type(), Blob: certAlwaysTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouch"},
				{Format: certAlwaysTouchWithCriticalOptions.Type(), Blob: certAlwaysTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouchWithCriticalOptions"},
				{Format: certCachedTouch.Type(), Blob: certCachedTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouch"},
				{Format: certCachedTouchWithCriticalOptions.Type(), Blob: certCachedTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouchWithCriticalOptions"},
				{Format: certTouchlessInAgent.Type(), Blob: certTouchlessInAgent.Marshal(), Comment: "TouchlessInAgentSSH-a7af667d-certTouchlessInAgent"},
				{Format: certTouchlessInAgentWithCriticalOptions.Type(), Blob: certTouchlessInAgentWithCriticalOptions.Marshal(), Comment: "TouchlessInAgentSSH-a7af667d-certTouchlessInAgentWithCriticalOptions"},
				{Format: certTouchless.Type(), Blob: certTouchless.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchless"},
				{Format: certTouchlessWithCriticalOptions.Type(), Blob: certTouchlessWithCriticalOptions.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchlessWithCriticalOptions"},
			},
		},
		"All with no-upstream": {
			NoUpstream:                      true,
			TouchlessInAgent:                true,
			Touchless:                       true,
			CachedTouch:                     true,
			AlwaysTouch:                     true,
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal(), Comment: "InAgentKey"},
				{Format: certAlwaysTouch.Type(), Blob: certAlwaysTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouch"},
				{Format: certAlwaysTouchWithCriticalOptions.Type(), Blob: certAlwaysTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouchWithCriticalOptions"},
				{Format: certCachedTouch.Type(), Blob: certCachedTouch.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouch"},
				{Format: certCachedTouchWithCriticalOptions.Type(), Blob: certCachedTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouchWithCriticalOptions"},
				{Format: certTouchless.Type(), Blob: certTouchless.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchless"},
				{Format: certTouchlessWithCriticalOptions.Type(), Blob: certTouchlessWithCriticalOptions.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchlessWithCriticalOptions"},
			},
		},
		"Key and Certs with Critical Options": {
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal(), Comment: "InAgentKey"},
				{Format: certAlwaysTouchWithCriticalOptions.Type(), Blob: certAlwaysTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouchWithCriticalOptions"},
				{Format: certCachedTouchWithCriticalOptions.Type(), Blob: certCachedTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouchWithCriticalOptions"},
				{Format: certTouchlessInAgentWithCriticalOptions.Type(), Blob: certTouchlessInAgentWithCriticalOptions.Marshal(), Comment: "TouchlessInAgentSSH-a7af667d-certTouchlessInAgentWithCriticalOptions"},
				{Format: certTouchlessWithCriticalOptions.Type(), Blob: certTouchlessWithCriticalOptions.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchlessWithCriticalOptions"},
			},
		},
		"Key and Certs with Critical Options and no-upstream": {
			NoUpstream:                      true,
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal(), Comment: "InAgentKey"},
				{Format: certAlwaysTouchWithCriticalOptions.Type(), Blob: certAlwaysTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certAlwaysTouchWithCriticalOptions"},
				{Format: certCachedTouchWithCriticalOptions.Type(), Blob: certCachedTouchWithCriticalOptions.Marshal(), Comment: "TouchSudoSSH-a7af667d-certCachedTouchWithCriticalOptions"},
				{Format: certTouchlessWithCriticalOptions.Type(), Blob: certTouchlessWithCriticalOptions.Marshal(), Comment: "TouchlessSSH-a7af667d-certTouchlessWithCriticalOptions"},
			},
		},
		"Empty": {},
	}

	// Randomly add certs and key
	for k, tt := range tests {
		t.Run(k, func(t *testing.T) {
			server := testServer(t, tt.NoUpstream)

			var once sync.Once
			addPrivKey := func() {
				once.Do(func() {
					if err := server.Add(ag.AddedKey{PrivateKey: priv, Comment: "InAgentKey"}); err != nil {
						t.Fatal(err)
					}
				})
			}

			var wg sync.WaitGroup

			sleep := func() {
				sleep, err := rand.Int(rand.Reader, big.NewInt(100))
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Duration(sleep.Int64()) * time.Microsecond)
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Always Touch cert.
				if tt.AlwaysTouch {
					addPrivKey()
					if err := server.AddHardCert(certAlwaysTouch, "certAlwaysTouch"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Always Touch cert with CriticalOptions.
				if tt.AlwaysTouchCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certAlwaysTouchWithCriticalOptions, "certAlwaysTouchWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Never Touch cert.
				if tt.Touchless {
					addPrivKey()
					if err := server.AddHardCert(certTouchless, "certTouchless"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Always Touch cert with CriticalOptions.
				if tt.AlwaysTouchCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certAlwaysTouchWithCriticalOptions, "certAlwaysTouchWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()
			// Create Never Touch in-agent cert.
			if tt.TouchlessInAgent {
				if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certTouchlessInAgent, Comment: "certTouchlessInAgent"}); err != nil {
					t.Fatal(err)
				}
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Cached Touch cert.
				if tt.CachedTouch {
					addPrivKey()
					if err := server.AddHardCert(certCachedTouch, "certCachedTouch"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Never Touch cert with CriticalOptions.
				if tt.TouchlessCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certTouchlessWithCriticalOptions, "certTouchlessWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Cached Touch cert with CriticalOptions.
				if tt.CachedTouchCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certCachedTouchWithCriticalOptions, "certCachedTouchWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Never Touch in-agent cert with CriticalOptions.
				if tt.TouchlessInAgentCriticalOptions {
					if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certTouchlessInAgentWithCriticalOptions, Comment: "certTouchlessInAgentWithCriticalOptions"}); err != nil {
						t.Error(err)
					}
				}
			}()
			wg.Wait()

			got, err := server.List()
			if err != nil {
				t.Fatalf("Got unexpected err: %v", err)
			}
			// Sort the keys by comments.
			sort.Slice(got, func(i, j int) bool {
				return got[i].Comment < got[j].Comment
			})
			if !cmp.Equal(got, tt.want) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v", cmp.Diff(got, tt.want))
			}
		})
	}
}

func TestSignersWithKetIDv1(t *testing.T) {
	t.Parallel()

	now := time.Now()

	priv, keyInAgent, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Create Always Touch cert.
	certAlwaysTouch := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a001"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certAlwaysTouch.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Always Touch cert with CriticalOptions.
	certAlwaysTouchWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a002"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certAlwaysTouchWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch cert.
	certTouchless := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a003"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certTouchless.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch in-agent cert.
	certTouchlessInAgent := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a004"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":true,"isHWKey":false,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certTouchlessInAgent.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Cached Touch cert.
	certCachedTouch := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a005"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certCachedTouch.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch cert with CriticalOptions.
	certTouchlessWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a006"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certTouchlessWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Cached Touch cert with CriticalOptions.
	certCachedTouchWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a007"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certCachedTouchWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Create Never Touch in-agent cert with CriticalOptions.
	certTouchlessInAgentWithCriticalOptions := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":["a008"],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":true,"isHWKey":false,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"critical": "critical"}},
	}
	if err := certTouchlessInAgentWithCriticalOptions.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		NoUpstream                      bool
		TouchlessInAgent                bool
		Touchless                       bool
		CachedTouch                     bool
		AlwaysTouch                     bool
		TouchlessInAgentCriticalOptions bool
		TouchlessCriticalOptions        bool
		CachedTouchCriticalOptions      bool
		AlwaysTouchCriticalOptions      bool
		want                            []ssh.PublicKey
	}{
		"Key and Certs": {
			TouchlessInAgent: true,
			Touchless:        true,
			CachedTouch:      true,
			AlwaysTouch:      true,
			want: []ssh.PublicKey{
				certAlwaysTouch,
				certTouchless,
				certTouchlessInAgent,
				certCachedTouch,
				keyInAgent,
			},
		},
		"Key and Certs with no-upstream": {
			NoUpstream:       true,
			TouchlessInAgent: true,
			Touchless:        true,
			CachedTouch:      true,
			AlwaysTouch:      true,
			want: []ssh.PublicKey{
				certAlwaysTouch,
				certTouchless,
				certCachedTouch,
				keyInAgent,
			},
		},
		"All": {
			TouchlessInAgent:                true,
			Touchless:                       true,
			CachedTouch:                     true,
			AlwaysTouch:                     true,
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []ssh.PublicKey{
				certAlwaysTouch,
				certAlwaysTouchWithCriticalOptions,
				certTouchless,
				certTouchlessInAgent,
				certCachedTouch,
				certTouchlessWithCriticalOptions,
				certCachedTouchWithCriticalOptions,
				certTouchlessInAgentWithCriticalOptions,
				keyInAgent,
			},
		},
		"All with no-upstream": {
			NoUpstream:                      true,
			TouchlessInAgent:                true,
			Touchless:                       true,
			CachedTouch:                     true,
			AlwaysTouch:                     true,
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []ssh.PublicKey{
				certAlwaysTouch,
				certAlwaysTouchWithCriticalOptions,
				certTouchless,
				certCachedTouch,
				certTouchlessWithCriticalOptions,
				certCachedTouchWithCriticalOptions,
				keyInAgent,
			},
		},
		"Key and Certs with Critical Options": {
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []ssh.PublicKey{
				certAlwaysTouchWithCriticalOptions,
				certTouchlessWithCriticalOptions,
				certCachedTouchWithCriticalOptions,
				certTouchlessInAgentWithCriticalOptions,
				keyInAgent,
			},
		},
		"Key and Certs with Critical Options and no-upstream": {
			NoUpstream:                      true,
			TouchlessInAgentCriticalOptions: true,
			TouchlessCriticalOptions:        true,
			CachedTouchCriticalOptions:      true,
			AlwaysTouchCriticalOptions:      true,
			want: []ssh.PublicKey{
				certAlwaysTouchWithCriticalOptions,
				certTouchlessWithCriticalOptions,
				certCachedTouchWithCriticalOptions,
				keyInAgent,
			},
		},
		"Empty": {},
	}

	comparer := cmp.Options{
		cmp.Comparer(func(x, y ssh.PublicKey) bool {
			return bytes.Equal(x.Marshal(), y.Marshal())
		}),
	}

	// Randomly add certs and key
	for k, tt := range tests {
		t.Run(k, func(t *testing.T) {
			server := testServer(t, tt.NoUpstream)

			var once sync.Once
			addPrivKey := func() {
				once.Do(func() {
					if err := server.Add(ag.AddedKey{PrivateKey: priv, Comment: "InAgentKey"}); err != nil {
						t.Fatal(err)
					}
				})
			}

			var wg sync.WaitGroup

			sleep := func() {
				sleep, err := rand.Int(rand.Reader, big.NewInt(100))
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Duration(sleep.Int64()) * time.Microsecond)
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Always Touch cert.
				if tt.AlwaysTouch {
					addPrivKey()
					if err := server.AddHardCert(certAlwaysTouch, "certAlwaysTouch"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Always Touch cert with CriticalOptions.
				if tt.AlwaysTouchCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certAlwaysTouchWithCriticalOptions, "certAlwaysTouchWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Never Touch cert.
				if tt.Touchless {
					addPrivKey()
					if err := server.AddHardCert(certTouchless, "certTouchless"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Always Touch cert with CriticalOptions.
				if tt.AlwaysTouchCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certAlwaysTouchWithCriticalOptions, "certAlwaysTouchWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()
			// Create Never Touch in-agent cert.
			if tt.TouchlessInAgent {
				if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certTouchlessInAgent, Comment: "certTouchlessInAgent"}); err != nil {
					t.Fatal(err)
				}
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Cached Touch cert.
				if tt.CachedTouch {
					addPrivKey()
					if err := server.AddHardCert(certCachedTouch, "certCachedTouch"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Never Touch cert with CriticalOptions.
				if tt.TouchlessCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certTouchlessWithCriticalOptions, "certTouchlessWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Cached Touch cert with CriticalOptions.
				if tt.CachedTouchCriticalOptions {
					addPrivKey()
					if err := server.AddHardCert(certCachedTouchWithCriticalOptions, "certCachedTouchWithCriticalOptions"); err != nil {
						t.Error(err)
					}
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				sleep()

				// Create Never Touch in-agent cert with CriticalOptions.
				if tt.TouchlessInAgentCriticalOptions {
					if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certTouchlessInAgentWithCriticalOptions, Comment: "certTouchlessInAgentWithCriticalOptions"}); err != nil {
						t.Error(err)
					}
				}
			}()
			wg.Wait()

			got, err := server.Signers()
			if err != nil {
				t.Fatalf("Got unexpected err: %v", err)
			}

			var keys []ssh.PublicKey
			for _, signer := range got {
				keys = append(keys, signer.PublicKey())
			}
			// Sort the keys by KeyID.
			sort.Slice(keys, func(i, j int) bool {
				cert1, err := key.CastSSHPublicKeyToCertificate(keys[i])
				if err != nil {
					return false
				}
				cert2, err := key.CastSSHPublicKeyToCertificate(keys[j])
				if err != nil {
					return true
				}
				return cert1.KeyId < cert2.KeyId
			})
			if !cmp.Equal(keys, tt.want, comparer) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v", cmp.Diff(keys, tt.want, comparer))
			}
		})
	}
}

func TestServer_AddHardCert(t *testing.T) {
	t.Parallel()

	now := time.Now()

	priv, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	certValidSSHCA := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certValidSSHCA.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	certInvalidSSHCA := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       "invalid-Not-SSHCA-CERT",
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certInvalidSSHCA.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                string
		addPrivKey          bool
		addValidSSHCACert   bool
		addInvalidSSHCACert bool
		wantInMemory        map[hashcode]*certificate
		wantErr             bool
	}{
		{
			name:              "key in agent and valid SSHCA cert",
			addPrivKey:        true,
			addValidSSHCACert: true,
			wantInMemory: map[hashcode]*certificate{
				hash(certValidSSHCA.Marshal()): {
					Certificate: certValidSSHCA,
					Blob:        certValidSSHCA.Marshal(),
					Comment:     "TouchSudoSSH-a7af667d-suffix",
				},
			},
		},
		{
			name:                "key in agent and invalid SSHCA cert",
			addPrivKey:          true,
			addInvalidSSHCACert: true,
			wantInMemory: map[hashcode]*certificate{
				hash(certInvalidSSHCA.Marshal()): {
					Certificate: certInvalidSSHCA,
					Blob:        certInvalidSSHCA.Marshal(),
					Comment:     "suffix",
				},
			},
		},
		{
			name:              "no valid key in agent and valid SSHCA cert",
			addValidSSHCACert: true,
			wantInMemory:      map[hashcode]*certificate{},
			wantErr:           true,
		},
		{
			name:                "no valid key in agent and invalid SSHCA cert",
			addInvalidSSHCACert: true,
			wantInMemory:        map[hashcode]*certificate{},
			wantErr:             true,
		},
	}

	comparer := cmp.Options{
		cmp.Comparer(func(x, y *ssh.Certificate) bool {
			return bytes.Equal(x.Marshal(), y.Marshal())
		}),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := testServer(t, true)

			if tt.addPrivKey {
				if err := server.Add(ag.AddedKey{PrivateKey: priv}); err != nil {
					t.Fatal(err)
				}
			}

			if tt.addValidSSHCACert {
				if err := server.AddHardCert(certValidSSHCA, "suffix"); (err != nil) != tt.wantErr {
					t.Errorf("unexpected error, got: %v, wantErr %v", err, tt.wantErr)
				}
			}

			if tt.addInvalidSSHCACert {
				if err := server.AddHardCert(certInvalidSSHCA, "suffix"); (err != nil) != tt.wantErr {
					t.Errorf("unexpected error, got: %v, wantErr %v", err, tt.wantErr)
				}
			}

			if !cmp.Equal(server.(*Server).certs, tt.wantInMemory, comparer...) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v",
					cmp.Diff(server.(*Server).certs, tt.wantInMemory, comparer...))
			}
		})
	}
}

func TestServer_Sign(t *testing.T) {
	t.Parallel()

	now := time.Now()

	priv, keyInAgent, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privOrphan, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signerOrphan, err := ssh.NewSignerFromKey(privOrphan)
	if err != nil {
		t.Fatal(err)
	}

	certOrphan := &ssh.Certificate{
		Key:         signerOrphan.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certOrphan.SignCert(rand.Reader, signerOrphan); err != nil {
		t.Fatal(err)
	}

	certExpiredInMemory := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(-time.Minute).Unix()),
	}
	if err := certExpiredInMemory.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	certExpiredInAgent := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(-time.Minute).Unix()),
	}
	if err := certExpiredInAgent.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	certValidSSHCAInMemory := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":2,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certValidSSHCAInMemory.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	certValidSSHCAInAgent := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":true,"isHWKey":false,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certValidSSHCAInAgent.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	// Both isHeadless and isHardware are true.
	certInvalidSSHCAInAgent := &ssh.Certificate{
		Key:         signer.PublicKey(),
		KeyId:       `{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":true,"isNonce":false,"touchPolicy":1,"ver":1}`,
		ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
		ValidBefore: uint64(now.Add(time.Hour).Unix()),
	}
	if err := certInvalidSSHCAInAgent.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		noUpstream bool
		pub        ssh.PublicKey
		wantKeys   []*ag.Key
		wantErr    bool
	}{
		{
			name: "sign with in-memory cert",
			pub:  certValidSSHCAInMemory,
			wantKeys: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal()},
				{Format: certValidSSHCAInMemory.Type(), Blob: certValidSSHCAInMemory.Marshal(), Comment: "TouchSudoSSH-a7af667d-validSSHCA"},
				{Format: certValidSSHCAInAgent.Type(), Blob: certValidSSHCAInAgent.Marshal(), Comment: "TouchlessInAgentSSH-a7af667d-validSSHCAInAgent"},
				{Format: certInvalidSSHCAInAgent.Type(), Blob: certInvalidSSHCAInAgent.Marshal(), Comment: "invalidSSHCAInAgent"},
			},
		},
		{
			name: "sign with in-agent cert",
			pub:  certValidSSHCAInAgent,
			wantKeys: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal()},
				{Format: certValidSSHCAInMemory.Type(), Blob: certValidSSHCAInMemory.Marshal(), Comment: "TouchSudoSSH-a7af667d-validSSHCA"},
				{Format: certValidSSHCAInAgent.Type(), Blob: certValidSSHCAInAgent.Marshal(), Comment: "TouchlessInAgentSSH-a7af667d-validSSHCAInAgent"},
				{Format: certInvalidSSHCAInAgent.Type(), Blob: certInvalidSSHCAInAgent.Marshal(), Comment: "invalidSSHCAInAgent"},
			},
		},
		{
			name:       "cannot sign with in-agent SSHCA cert with no-upstream",
			noUpstream: true,
			pub:        certValidSSHCAInAgent,
			wantKeys: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal()},
				{Format: certValidSSHCAInMemory.Type(), Blob: certValidSSHCAInMemory.Marshal(), Comment: "TouchSudoSSH-a7af667d-validSSHCA"},
				{Format: certInvalidSSHCAInAgent.Type(), Blob: certInvalidSSHCAInAgent.Marshal(), Comment: "invalidSSHCAInAgent"},
			},
			wantErr: true,
		},
		{
			name:       "sign with in-agent non-SSHCA cert with no-upstream",
			noUpstream: true,
			pub:        certInvalidSSHCAInAgent,
			wantKeys: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal()},
				{Format: certValidSSHCAInMemory.Type(), Blob: certValidSSHCAInMemory.Marshal(), Comment: "TouchSudoSSH-a7af667d-validSSHCA"},
				{Format: certInvalidSSHCAInAgent.Type(), Blob: certInvalidSSHCAInAgent.Marshal(), Comment: "invalidSSHCAInAgent"},
			},
		},
		{
			name:       "sign with in-agent key with no-upstream",
			noUpstream: true,
			pub:        keyInAgent,
			wantKeys: []*ag.Key{
				{Format: keyInAgent.Type(), Blob: keyInAgent.Marshal()},
				{Format: certValidSSHCAInMemory.Type(), Blob: certValidSSHCAInMemory.Marshal(), Comment: "TouchSudoSSH-a7af667d-validSSHCA"},
				{Format: certInvalidSSHCAInAgent.Type(), Blob: certInvalidSSHCAInAgent.Marshal(), Comment: "invalidSSHCAInAgent"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := testServer(t, tt.noUpstream)

			server.(*Server).certs[hash(certOrphan.Marshal())] = &certificate{
				Certificate: certOrphan,
				Blob:        certOrphan.Marshal(),
				Comment:     "orphan",
			}

			if err := server.Add(ag.AddedKey{PrivateKey: priv}); err != nil {
				t.Fatal(err)
			}
			if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certExpiredInAgent, Comment: "expired"}); err != nil {
				t.Fatal(err)
			}
			if err := server.AddHardCert(certExpiredInMemory, "expired"); err != nil {
				t.Fatal(err)
			}

			if err := server.AddHardCert(certValidSSHCAInMemory, "validSSHCA"); err != nil {
				t.Fatal(err)
			}
			if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certValidSSHCAInAgent, Comment: "validSSHCAInAgent"}); err != nil {
				t.Fatal(err)
			}
			if err := server.Add(ag.AddedKey{PrivateKey: priv, Certificate: certInvalidSSHCAInAgent, Comment: "invalidSSHCAInAgent"}); err != nil {
				t.Fatal(err)
			}

			data := make([]byte, 1024)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}

			if sig, err := server.Sign(tt.pub, data); (err != nil) != tt.wantErr {
				t.Errorf("unexpected error, got: %v, wantErr: %v", err, tt.wantErr)
			} else if err == nil {
				if err := tt.pub.Verify(data, sig); err != nil {
					t.Errorf("unexpected error, got: %v", err)
				}
			}

			keys, err := server.List()
			if err != nil {
				t.Fatal(err)
			}
			// Sort the keys by comments.
			sort.Slice(keys, func(i, j int) bool {
				return keys[i].Comment < keys[j].Comment
			})
			if !cmp.Equal(keys, tt.wantKeys) {
				t.Errorf("unexpected result, diff(-got,+want):\n%v",
					cmp.Diff(keys, tt.wantKeys))
			}
		})
	}
}
