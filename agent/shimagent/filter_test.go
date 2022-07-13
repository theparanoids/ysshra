// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package shimagent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// helperGenerateKey creates public and private key.
func helperGenerateKey(t *testing.T) (*rsa.PrivateKey, ssh.Signer, ssh.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return priv, signer, pub
}

type matcherSSHCertificate ssh.Certificate

func (yc *matcherSSHCertificate) Matches(x interface{}) bool {
	if xc, ok := x.(*ssh.Certificate); !ok {
		return false
	} else {
		return bytes.Equal(xc.Marshal(), (*ssh.Certificate)(yc).Marshal())
	}
}

func (yc *matcherSSHCertificate) String() string {
	return fmt.Sprint(string(ssh.MarshalAuthorizedKey((*ssh.Certificate)(yc))))
}

func Test_filterExpiredCerts(t *testing.T) {
	t.Parallel()

	_, caSigner, _ := helperGenerateKey(t)
	_, _, validPub := helperGenerateKey(t)
	valid := &ssh.Certificate{
		Key:         validPub,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := valid.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	_, _, expiredPub := helperGenerateKey(t)
	expired := &ssh.Certificate{
		Key:         expiredPub,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(-time.Minute).Unix()),
	}
	if err := expired.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	type input struct {
		server        helperShimAgentServer
		certsInMemory map[hashcode]*certificate
		keysInAgent   []*agent.Key
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T) input
		wantErr bool
	}{
		{
			name: "remove in-memory expired cert",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)
				server.EXPECT().remove((*matcherSSHCertificate)(expired)).Return(nil)

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(valid.Marshal()):   {Certificate: valid},
						hash(expired.Marshal()): {Certificate: expired},
					},
				}
				return input
			},
		},
		{
			name: "remove in-agent expired cert",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)
				server.EXPECT().remove((*matcherSSHCertificate)(expired)).Return(nil)

				input := input{
					server: server,
					keysInAgent: []*agent.Key{
						{Format: valid.Type(), Blob: valid.Marshal()},
						{Format: expired.Type(), Blob: expired.Marshal()},
					},
				}
				return input
			},
		},
		{
			name: "remove error",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)
				server.EXPECT().remove((*matcherSSHCertificate)(expired)).Return(errors.New("some error")).Times(2)

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(valid.Marshal()):   {Certificate: valid},
						hash(expired.Marshal()): {Certificate: expired},
					},
					keysInAgent: []*agent.Key{
						{Format: valid.Type(), Blob: valid.Marshal()},
						{Format: expired.Type(), Blob: expired.Marshal()},
					},
				}
				return input
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.setup(t)
			err := filterExpiredCerts(input.server, input.certsInMemory, input.keysInAgent)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error, got: %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				t.Log(err)
			}
		})
	}
}

type matcherSSHPublicKey struct {
	pub ssh.PublicKey
}

func (y matcherSSHPublicKey) Matches(x interface{}) bool {
	xk, ok := x.(ssh.PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(xk.Marshal(), y.pub.Marshal())
}

func (y matcherSSHPublicKey) String() string {
	return fmt.Sprint(string(ssh.MarshalAuthorizedKey(y.pub)))
}

func Test_filterOrphanCertsInMemory(t *testing.T) {
	t.Parallel()

	_, caSigner, _ := helperGenerateKey(t)
	secretKey, _, _ := helperGenerateKey(t)
	orphanKey, _, orphanPub := helperGenerateKey(t)
	orphanCert := &ssh.Certificate{
		Key:         orphanPub,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := orphanCert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	type input struct {
		server        helperShimAgentServer
		certsInMemory map[hashcode]*certificate
		keysInAgent   []*agent.Key
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T) input
		wantErr bool
	}{
		{
			name: "orphan cert in memory",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)
				server.EXPECT().remove(matcherSSHPublicKey{pub: orphanCert}).Return(nil)

				ag := agent.NewKeyring()
				if err := ag.Add(agent.AddedKey{PrivateKey: secretKey}); err != nil {
					t.Fatal(err)
				}
				keys, err := ag.List()
				if err != nil {
					t.Fatal(err)
				}

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(orphanCert.Marshal()): {Certificate: orphanCert},
					},
					keysInAgent: keys,
				}
				return input
			},
		},
		{
			name: "orphan cert in memory but fail to remove",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)
				server.EXPECT().remove(matcherSSHPublicKey{pub: orphanCert}).Return(errors.New("some err"))

				ag := agent.NewKeyring()
				if err := ag.Add(agent.AddedKey{PrivateKey: secretKey}); err != nil {
					t.Fatal(err)
				}
				keys, err := ag.List()
				if err != nil {
					t.Fatal(err)
				}

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(orphanCert.Marshal()): {Certificate: orphanCert},
					},
					keysInAgent: keys,
				}
				return input
			},
			wantErr: true,
		},
		{
			name: "don't remove orphan cert when on keys in agent",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(orphanCert.Marshal()): {Certificate: orphanCert},
					},
				}
				return input
			},
		},
		{
			name: "with cert in agent",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)

				ag := agent.NewKeyring()
				if err := ag.Add(agent.AddedKey{PrivateKey: orphanKey, Certificate: orphanCert}); err != nil {
					t.Fatal(err)
				}
				keys, err := ag.List()
				if err != nil {
					t.Fatal(err)
				}

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(orphanCert.Marshal()): {Certificate: orphanCert},
					},
					keysInAgent: keys,
				}
				return input
			},
		},
		{
			name: "with key in agent",
			setup: func(t *testing.T) input {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				server := NewMockhelperShimAgentServer(ctrl)

				ag := agent.NewKeyring()
				if err := ag.Add(agent.AddedKey{PrivateKey: orphanKey}); err != nil {
					t.Fatal(err)
				}
				keys, err := ag.List()
				if err != nil {
					t.Fatal(err)
				}

				input := input{
					server: server,
					certsInMemory: map[hashcode]*certificate{
						hash(orphanCert.Marshal()): {Certificate: orphanCert},
					},
					keysInAgent: keys,
				}
				return input
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.setup(t)
			err := filterOrphanCerts(input.server, input.certsInMemory, input.keysInAgent)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error, got: %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
