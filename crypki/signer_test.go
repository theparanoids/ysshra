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
	mockhelper "go.vzbuilders.com/peng/sshra-oss/crypki/mock"
	"go.vzbuilders.com/peng/sshra-oss/internal/backoff"
	"go.vzbuilders.com/peng/sshra-oss/sshutils/key"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
		s.Serve(listener)
	}()

	dialer := func(ctx context.Context, s string) (net.Conn, error) {
		return listener.Dial()
	}

	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(dialer),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(3),
			// Test retry and backoff in Millisecond.
			grpc_retry.WithPerRetryTimeout(5.0*time.Millisecond),
			grpc_retry.WithBackoff((&backoff.Config{
				BaseDelay:  30.0 * time.Millisecond,
				Multiplier: 3.0,
				MaxDelay:   500.0 * time.Millisecond,
				Jitter:     0.2,
			}).Backoff)),
		),
	}
	return mockServer, dialOpts
}

func TestNewSignerValidationFailed(t *testing.T) {
	t.Parallel()
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
		times       int
	}{
		"happy path": {
			csr:         validCSR,
			out:         &proto.SSHKey{Key: marshalledCert},
			expectedErr: nil,
			times:       1,
		},
		"invalid CSR": {
			csr:         invalidCSR,
			out:         &proto.SSHKey{},
			expectedErr: errors.New("bad request: cannot use key unknown"),
			times:       1,
		},
		"unavailable": {
			csr:         invalidCSR2,
			out:         &proto.SSHKey{},
			expectedErr: status.Error(codes.Unavailable, "transport is closing"),
			times:       3,
		},
		"server timeout": {
			csr:         invalidCSR3,
			out:         &proto.SSHKey{},
			expectedErr: status.Error(codes.DeadlineExceeded, "server request timeout"),
			times:       3,
		},
	}
	for name, tt := range table {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Hour)
		t.Run(name, func(t *testing.T) {
			mockServer, dialOpts := testMockGRPCServer(t)
			mockServer.
				EXPECT().
				PostUserSSHCertificate(gomock.Any(), mockhelper.String(tt.csr)).
				Return(tt.out, tt.expectedErr).Times(tt.times)
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

func TestNewSigner(t *testing.T) {
	t.Parallel()
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
