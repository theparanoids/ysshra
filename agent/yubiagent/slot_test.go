package yubiagent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	"github.com/theparanoids/ysshra/keyid"
	"golang.org/x/crypto/ssh"
)

func TestNewSlotAgent(t *testing.T) {
	t.Parallel()

	happyPathAttestCert := &x509.Certificate{
		PublicKey: &rsa.PublicKey{},
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
				Value: []byte{0, byte(keyid.NeverTouch)},
			},
		},
	}
	happyPathPublicKey, _ := ssh.NewPublicKey(happyPathAttestCert.PublicKey)

	tests := []struct {
		name       string
		attestCert *x509.Certificate
		attestErr  error
		code       string
		want       *SlotAgent
		wantErr    bool
	}{
		{
			name:       "happy path",
			code:       "9a",
			attestCert: happyPathAttestCert,
			want: &SlotAgent{
				attest: happyPathAttestCert,
				public: happyPathPublicKey,
				code:   "9a",
				policy: keyid.NeverTouch,
			},
		},
		{
			name:       "attest error",
			attestCert: nil,
			attestErr:  errors.New("failed to attest"),
			wantErr:    true,
		},
		{
			name: "RSA with affected firmware version",
			attestCert: &x509.Certificate{
				PublicKeyAlgorithm: x509.RSA,
				PublicKey:          &rsa.PublicKey{},
				Extensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
						Value: []byte{0, byte(keyid.NeverTouch)},
					},
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}, // firmware version
						Value: []byte{4, 3, 4},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported public key",
			attestCert: &x509.Certificate{
				PublicKey: "invalid string here",
				Extensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
						Value: []byte{0, byte(keyid.NeverTouch)},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			yubicoAgent := NewMockYubiAgent(mockCtrl)
			yubicoAgent.EXPECT().AttestSlot(tt.code).
				Return(tt.attestCert, tt.attestErr).Times(1)

			if tt.want != nil {
				tt.want.attest = tt.attestCert
				tt.want.public, _ = ssh.NewPublicKey(tt.attestCert.PublicKey)
				tt.want.yubiAgent = yubicoAgent
			}

			got, err := NewSlotAgent(yubicoAgent, tt.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSlot() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSlot() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateSSHPublicKeyAlgo(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		pub  crypto.PublicKey
		want bool
	}{
		{
			name: "happy path rsa",
			pub:  &priv.PublicKey,
			want: true,
		},
		{
			name: "happy path edcsa",
			pub:  &privEC.PublicKey,
			want: true,
		},
		{
			name: "invalid",
			pub:  "invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSSHPublicKeyAlgo(tt.pub); got != tt.want {
				t.Errorf("validateSSHPublicKeyAlgo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSlotAgent_RegisterCSRs(t *testing.T) {
	t.Parallel()
	s := &SlotAgent{}
	csrs := []*proto.SSHCertificateSigningRequest{
		{
			Principals: []string{"test01"},
			Validity:   3600,
		},
		{
			Principals: []string{"test02"},
			Validity:   3600,
		},
	}
	s.RegisterCSRs(csrs)
	if !reflect.DeepEqual(s.CSRs(), csrs) {
		t.Errorf("CSRs() got = %v, want %v", s.CSRs(), csrs)
	}
}

func TestSlotAgentFields(t *testing.T) {
	t.Parallel()
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	happyPathPublicKey, _ := ssh.NewPublicKey(ecdsa.PublicKey{})

	s := &SlotAgent{
		yubiAgent: NewMockYubiAgent(mockCtrl),
		code:      "test-code",
		public:    happyPathPublicKey,
		attest: &x509.Certificate{
			PublicKey: "invalid string here",
			Extensions: []pkix.Extension{
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7},
					Value: []byte("12345"),
				},
			},
		},
		policy: keyid.DefaultTouch,
	}
	if !reflect.DeepEqual(s.PublicKey(), s.public) {
		t.Errorf("PublicKey() got = %v, want %v", s.CSRs(), s.public)
	}
	if !reflect.DeepEqual(s.Agent(), s.yubiAgent) {
		t.Errorf("Agent() got = %v, want %v", s.CSRs(), s.yubiAgent)
	}
	if !reflect.DeepEqual(s.SlotCode(), s.code) {
		t.Errorf("SlotCode() got = %v, want %v", s.CSRs(), s.code)
	}
	if !reflect.DeepEqual(s.TouchPolicy(), s.policy) {
		t.Errorf("TouchPolicy() got = %v, want %v", s.CSRs(), s.policy)
	}
	if !reflect.DeepEqual(s.AttestCert(), s.attest) {
		t.Errorf("AttestCert() got = %v, want %v", s.CSRs(), s.attest)
	}
	serial, _ := s.Serial()
	wantSerial, _ := yubiattest.ModHex(s.attest)
	if !reflect.DeepEqual(serial, wantSerial) {
		t.Errorf("Serial() got = %v, want %v", serial, wantSerial)
	}
}
