// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSSHCertificate(t *testing.T, keyID string, permission *ssh.Permissions) (*ssh.Certificate, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Error(err)
	}
	if permission == nil {
		permission = &ssh.Permissions{}
	}
	crt := &ssh.Certificate{
		Permissions:     *permission,
		KeyId:           keyID,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"prins"},
		Key:             pub,
		ValidAfter:      uint64(time.Now().Unix()) - 1000,
		ValidBefore:     uint64(time.Now().Unix()) + 1000,
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Error(err)
	}
	if err := crt.SignCert(rand.Reader, signer); err != nil {
		t.Error(err)
	}
	return crt, priv
}

func TestValidateSSHCertTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		certNil     bool
		currentTime time.Time
		expectValid bool
	}{
		{
			name:        "valid-cert",
			certNil:     false,
			currentTime: time.Now(),
			expectValid: true,
		},
		{
			name:        "expired-cert",
			certNil:     false,
			currentTime: time.Now().Add(time.Hour * 24),
			expectValid: false,
		},
		{
			name:        "expired-cert-current-zero",
			certNil:     false,
			currentTime: time.Time{},
			expectValid: false,
		},
		{
			name:        "future-cert",
			certNil:     false,
			currentTime: time.Now().Add(-time.Hour * 24),
			expectValid: false,
		},
		{
			name:        "nil-cert",
			certNil:     true,
			currentTime: time.Now(),
			expectValid: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert, _ := testSSHCertificate(t, "keyID", nil)
			if tt.certNil {
				cert = nil
			}
			ret := ValidateSSHCertTime(cert, tt.currentTime)
			if ret != tt.expectValid {
				t.Errorf("mismatch in the return value, got: %v, want: %v", ret, tt.expectValid)
			}
		})
	}
}
