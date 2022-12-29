package yubiagent

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/golang/mock/gomock"
	"github.com/theparanoids/ysshra/keyid"
	"go.ouryahoo.com/peng/sshca/key"
	"go.ouryahoo.com/peng/sshca/sshra/gensign/mock"
)

const projectPath = "./../../../../.."

func readTestCert(t *testing.T, publicKeyAlgo x509.PublicKeyAlgorithm, slot string) (cert *x509.Certificate) {
	var path string
	if publicKeyAlgo == x509.RSA {
		path = fmt.Sprintf("%s/sshra/tests/keys/%s.crt", projectPath, slot)
	} else {
		path = fmt.Sprintf("%s/sshra/tests/keys/%s-ecdsa.crt", projectPath, slot)
	}
	output, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = key.ParsePEMCertificate(output)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func readTestPublicKey(t *testing.T, publicKeyAlgo x509.PublicKeyAlgorithm, slot string) (key ssh.PublicKey) {
	cert := readTestCert(t, publicKeyAlgo, slot)
	key, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNewSlot(t *testing.T) {
	type args struct {
		attestCert *x509.Certificate
		err        error
		code       string
	}
	tests := []struct {
		name    string
		args    args
		want    *yubiKeySlot
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				attestCert: &x509.Certificate{
					PublicKey: &rsa.PublicKey{},
					Extensions: []pkix.Extension{
						{
							Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
							Value: []byte{0, byte(keyid.AlwaysTouch)},
						},
					},
				},
				code: "9a",
			},
			want: &yubiKeySlot{
				attest: nil, // should be updated according to the attestCert
				public: nil, // should be updated according to the publicKey in attestCert
				code:   "9a",
				policy: keyid.AlwaysTouch,
			},
		},
		{
			name: "attest error",
			args: args{
				attestCert: nil,
				err:        errors.New("failed to attest"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			if tt.want != nil {
				tt.want.attest = tt.args.attestCert
				tt.want.public, _ = ssh.NewPublicKey(tt.args.attestCert.PublicKey)
			}

			yubicoAgent := mock.NewMockYubiAgent(mockCtrl)
			yubicoAgent.EXPECT().AttestSlot(tt.args.code).
				Return(tt.args.attestCert, tt.args.err).Times(1)

			got, err := Slot(yubicoAgent, tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("Slot() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Slot() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_slot_attestSlot(t *testing.T) {
	type fields struct {
		code   string
		public ssh.PublicKey
		attest *x509.Certificate
		policy keyid.TouchPolicy
	}
	type args struct {
		f9Cert    *x509.Certificate
		pivRootCA string
		u2fRootCA string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				f9Cert: readTestCert(t, x509.RSA, "f9"),
			},
			fields: fields{
				code:   "9a",
				public: readTestPublicKey(t, x509.ECDSA, "9a"),
				attest: readTestCert(t, x509.ECDSA, "9a-attest"),
			},
		},
		{
			name: "RSA should be denied",
			args: args{
				f9Cert: readTestCert(t, x509.RSA, "f9"),
			},
			fields: fields{
				code:   "9a",
				public: readTestPublicKey(t, x509.RSA, "9a"),
				attest: readTestCert(t, x509.RSA, "9a-attest"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &yubiKeySlot{
				code:   tt.fields.code,
				public: tt.fields.public,
				attest: tt.fields.attest,
				policy: tt.fields.policy,
			}
			if err := s.attestSlot(tt.args.f9Cert, tt.args.pivRootCA, tt.args.u2fRootCA); (err != nil) != tt.wantErr {
				t.Errorf("attestSlot() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetTouchPolicyWithoutAttCert(t *testing.T) {
	if touch := getTouchPolicy(nil); touch != keyid.DefaultTouch {
		t.Errorf("expected default touch policy, got %v", touch)
	}
}

func TestGetTouchPolicySuccess(t *testing.T) {
	table := []struct {
		slot    string
		keyAlgo x509.PublicKeyAlgorithm
		want    keyid.TouchPolicy
	}{
		{"9a", x509.RSA, keyid.DefaultTouch},      // un-attested cert
		{"9a-attest", x509.RSA, keyid.NeverTouch}, // attested cert
	}

	for _, tt := range table {
		cert := readTestCert(t, tt.keyAlgo, tt.slot)
		if got := getTouchPolicy(cert); got != tt.want {
			t.Errorf("touch policy doesn't match, expected %v, got %v", tt.want, got)
		}
	}
}
