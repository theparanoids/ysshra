// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/theparanoids/crypki/proto"
	mockhelper "github.com/theparanoids/ysshra/crypki/mock"
	"github.com/theparanoids/ysshra/internal/backoff"
	"github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	bufSize = 1024 * 1024
)

func testSSHCertificate(t *testing.T, prins ...string) (*ssh.Certificate, *rsa.PrivateKey) {
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
	return crt, priv
}

func testMockGRPCServer(t *testing.T) (*proto.MockSigningServer, []grpc.DialOption) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockServer := proto.NewMockSigningServer(ctrl)

	listener := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	t.Cleanup(func() {
		listener.Close()
	})

	proto.RegisterSigningServer(s, mockServer)
	go func() {
		t.Cleanup(func() {
			s.Stop()
		})
		if err := s.Serve(listener); err != nil {
			t.Error(err)
		}
	}()

	dialer := func(ctx context.Context, s string) (net.Conn, error) {
		return listener.Dial()
	}

	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	return mockServer, dialOpts
}

func TestNewSignerValidationFailed(t *testing.T) {
	_, err := NewSigner(SignerConfig{
		TLSClientKeyFile: "key",
	})
	expected := `TLSClientCertFile' failed on the 'required' tag`
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("got err %s, want %s", err.Error(), expected)
	}
	if err == nil {
		t.Fatalf("%s: want error but got no error", t.Name())
	}
}

func TestSignerPostUserSSHCertificate(t *testing.T) {
	// Disable parallel to prevent race condition with TestSignerPostUserSSHCertificateBackoffTimeoutRetry.
	// Both test cases rely on the mock grpc server.
	// t.Parallel()
	validCSR := &proto.SSHCertificateSigningRequest{
		KeyMeta:    &proto.KeyMeta{Identifier: "key-identifier"},
		Principals: []string{"testuser"},
	}
	invalidCSR := &proto.SSHCertificateSigningRequest{
		KeyMeta: &proto.KeyMeta{Identifier: "unknown"},
	}
	invalidCSR2 := &proto.SSHCertificateSigningRequest{
		KeyMeta: &proto.KeyMeta{Identifier: "unknown2"},
	}
	invalidCSR3 := &proto.SSHCertificateSigningRequest{
		KeyMeta: &proto.KeyMeta{Identifier: "key-identifier"},
	}

	validCert, _ := testSSHCertificate(t, "testuser")
	marshalledCert := string(ssh.MarshalAuthorizedKey(validCert))

	table := map[string]struct {
		csr         *proto.SSHCertificateSigningRequest
		out         *proto.SSHKey
		expectedErr error
	}{
		"happy path": {
			csr:         validCSR,
			out:         &proto.SSHKey{Key: marshalledCert},
			expectedErr: nil,
		},
		"invalid CSR": {
			csr:         invalidCSR,
			out:         &proto.SSHKey{},
			expectedErr: errors.New("bad request: cannot use key unknown"),
		},
		"unavailable": {
			csr:         invalidCSR2,
			out:         &proto.SSHKey{},
			expectedErr: status.Error(codes.Unavailable, "transport is closing"),
		},
		"deadline exceeded": {
			csr:         invalidCSR3,
			out:         &proto.SSHKey{},
			expectedErr: status.Error(codes.DeadlineExceeded, "server request timeout"),
		},
	}
	for name, tt := range table {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Run(name, func(t *testing.T) {
			mockServer, dialOpts := testMockGRPCServer(t)
			mockServer.
				EXPECT().
				PostUserSSHCertificate(gomock.Any(), mockhelper.String(tt.csr)).
				Return(tt.out, tt.expectedErr).AnyTimes()
			s := Signer{
				dialOptions: dialOpts,
			}
			got, _, err := s.postUserSSHCertificate(ctx, tt.csr, "")
			want, _, _ := key.GetPublicKeysFromBytes([]byte(tt.out.Key))
			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("expected error for invalid test %v, got nil", name)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for test %v, err: %v", name, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("output doesn't match, got %v, want %v", got, want)
				}
			}
			if name == "client timeout" {
				cancel()
			}
		})
	}
}

func TestSignerPostUserSSHCertificateBackoffTimeoutRetry(t *testing.T) {
	// Disable parallel to prevent race condition with TestSignerPostUserSSHCertificate.
	// Both test cases rely on the mock grpc server.
	// t.Parallel()
	invalidCSR := &proto.SSHCertificateSigningRequest{
		KeyMeta: &proto.KeyMeta{Identifier: "unknown"},
	}

	expectedErr := status.Error(codes.DeadlineExceeded, "server request timeout")
	expectedRetryTimes := 3

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	mockServer, dialOpts := testMockGRPCServer(t)
	dialOpts = append(dialOpts,
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(uint(expectedRetryTimes)),
			// Test retry and backoff in Millisecond.
			grpc_retry.WithPerRetryTimeout(100.0*time.Millisecond),
			grpc_retry.WithBackoff((&backoff.Config{
				BaseDelay:  30.0 * time.Millisecond,
				Multiplier: 3.0,
				MaxDelay:   500.0 * time.Millisecond,
			}).Backoff))))
	mockServer.
		EXPECT().
		PostUserSSHCertificate(gomock.Any(), mockhelper.String(invalidCSR)).
		Return(&proto.SSHKey{}, expectedErr).Times(expectedRetryTimes)
	s := Signer{
		dialOptions: dialOpts,
	}
	_, _, err := s.postUserSSHCertificate(ctx, invalidCSR, "")
	if err == nil {
		t.Errorf("expected error for the test, got nil")
	}
}

func TestNewSigner(t *testing.T) {
	tests := []struct {
		name    string
		conf    SignerConfig
		want    *Signer
		wantErr bool
	}{
		{
			name: "happy path",
			conf: SignerConfig{
				TLSClientCertFile: "./testdata/client.crt",
				TLSClientKeyFile:  "./testdata/client.key",
				TLSCACertFiles:    []string{"./testdata/ca.crt"},
				CrypkiEndpoints:   []string{"fake-crypki"},
				CrypkiPort:        4443,
				Retries:           10,
			},
			want: &Signer{
				endpoints: []string{"fake-crypki:4443"},
			},
		},
		{
			name: "endpoint missing",
			conf: SignerConfig{
				TLSClientCertFile: "./testdata/client.crt",
				TLSClientKeyFile:  "./testdata/client.key",
				TLSCACertFiles:    []string{"./testdata/ca.crt"},
				CrypkiPort:        4443,
				Retries:           10,
			},
			wantErr: true,
		},
		{
			name: "tls client missing",
			conf: SignerConfig{
				TLSClientKeyFile: "./testdata/client.key",
				TLSCACertFiles:   []string{"./testdata/ca.crt"},
				CrypkiEndpoints:  []string{"fake-crypki"},
				CrypkiPort:       4443,
				Retries:          10,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.conf)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			got.dialOptions = nil
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() got = %v, want %v", got, tt.want)
			}
		})
	}
}
