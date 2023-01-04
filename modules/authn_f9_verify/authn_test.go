package authn_f9_verify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/theparanoids/ysshra/agent/yubiagent"
)

func testSignX509Cert(unsignedCert, caCert *x509.Certificate, pubKey *rsa.PublicKey,
	caPrivKey *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, unsignedCert, caCert, pubKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pem := pem.EncodeToMemory(&b)

	return cert, pem, nil
}

func testSelfSignX509Cert() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	return testSelfSignX509CertWithBits(2048)
}

func testSelfSignX509CertWithBits(bits int) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	var unsignedCert = &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		PublicKeyAlgorithm: x509.ECDSA,
		IsCA:               true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, pem, err := testSignX509Cert(unsignedCert, unsignedCert, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pem, priv, nil
}

func testGenSignX509Cert(caCert *x509.Certificate, caKey *rsa.PrivateKey,
	priv *rsa.PrivateKey, yubikeyHexDecimal []byte) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	if priv == nil {
		var err error
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	var unsignedCert = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageCRLSign,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7},
				Value: yubikeyHexDecimal,
			},
		},
	}

	cert, pem, err := testSignX509Cert(unsignedCert, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pem, priv, err
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		agent   func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{})
		want    *authn
		wantErr bool
	}{
		{
			name: "happy path",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				defer mockCtrl.Finish()
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				return yubicoAgent, map[string]interface{}{
					"f9_certs_dir": "/path/to/f9/certs",
				}
			},
			want: &authn{
				f9CertsDir: "/path/to/f9/certs",
			},
		},
		{
			name: "invalid module conf",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				mockCtrl := gomock.NewController(t)
				defer mockCtrl.Finish()
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				return yubicoAgent, map[string]interface{}{
					"f9_certs_dir": 123,
				}
			},
			wantErr: true,
		},
		{
			name: "not yubiagent",
			agent: func(t *testing.T) (yubiagent.YubiAgent, map[string]interface{}) {
				return nil, nil
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag, c := tt.agent(t)
			got, err := New(ag, c)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			gotMod, ok := got.(*authn)
			if !ok {
				t.Errorf("the module is not the correct authn")
			}
			tt.want.agent = ag
			if !reflect.DeepEqual(gotMod, tt.want) {
				t.Errorf("New() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authn_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		agent   func(t *testing.T) (yubiagent.YubiAgent, string)
		wantErr bool
	}{
		{
			name: "happy path",
			agent: func(t *testing.T) (yubiagent.YubiAgent, string) {
				tmpDir := t.TempDir()

				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				// "02:04:04:03:02:01" is the HEX Decimal encoding of the yubikey serial number.
				// The first byte (`02`) indicates that the type is integer.
				// The second byte (`04`) denotes the number of bytes of the value.
				// The rest of the bytes (`04`, `03`, `02`, `01`) can be converted to
				// modhex `cfcecdcb` and decimal `67305985`.
				cert, certByte, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{02, 04, 04, 03, 02, 01})
				if err != nil {
					t.Fatal(err)
				}

				serialPath := path.Join(tmpDir, "67305985.pem")
				if err := os.WriteFile(serialPath, certByte, 0644); err != nil {
					t.Fatal(err)
				}

				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().ReadSlot("f9").Return(cert, nil).Times(1)
				return yubicoAgent, serialPath
			},
		},
		{
			name: "invalid yx509 cert",
			agent: func(t *testing.T) (yubiagent.YubiAgent, string) {
				invalidCert, _, _, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().ReadSlot("f9").Return(invalidCert, nil).Times(1)
				return yubicoAgent, ""
			},
			wantErr: true,
		},
		{
			name: "agent error",
			agent: func(t *testing.T) (yubiagent.YubiAgent, string) {
				invalidCert, _, _, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().ReadSlot("f9").Return(invalidCert, errors.New("some error")).Times(1)
				return yubicoAgent, ""
			},
			wantErr: true,
		},
		{
			name: "f9 cert not found",
			agent: func(t *testing.T) (yubiagent.YubiAgent, string) {
				tmpDir := t.TempDir()

				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				cert, certByte, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{02, 04, 04, 03, 02, 01})
				if err != nil {
					t.Fatal(err)
				}

				serialPath := path.Join(tmpDir, "invalid_path.pem")
				if err := os.WriteFile(serialPath, certByte, 0644); err != nil {
					t.Fatal(err)
				}

				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().ReadSlot("f9").Return(cert, nil).Times(1)
				return yubicoAgent, serialPath
			},
			wantErr: true,
		},
		{
			name: "invalid cert at path",
			agent: func(t *testing.T) (yubiagent.YubiAgent, string) {
				tmpDir := t.TempDir()

				caCert, _, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				cert, _, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{02, 04, 04, 03, 02, 01})
				if err != nil {
					t.Fatal(err)
				}

				serialPath := path.Join(tmpDir, "67305985.pem")
				if err := os.WriteFile(serialPath, []byte("invalid-cert-bytes"), 0644); err != nil {
					t.Fatal(err)
				}

				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().ReadSlot("f9").Return(cert, nil).Times(1)
				return yubicoAgent, serialPath
			},
			wantErr: true,
		},
		{
			name: "f9 cert not equal",
			agent: func(t *testing.T) (yubiagent.YubiAgent, string) {
				tmpDir := t.TempDir()

				caCert, caByte, caPriv, err := testSelfSignX509Cert()
				if err != nil {
					t.Fatal(err)
				}
				cert, _, _, err := testGenSignX509Cert(caCert, caPriv, nil, []byte{02, 04, 04, 03, 02, 01})
				if err != nil {
					t.Fatal(err)
				}

				serialPath := path.Join(tmpDir, "67305985.pem")
				if err := os.WriteFile(serialPath, caByte, 0644); err != nil {
					t.Fatal(err)
				}

				mockCtrl := gomock.NewController(t)
				t.Cleanup(mockCtrl.Finish)
				yubicoAgent := yubiagent.NewMockYubiAgent(mockCtrl)
				yubicoAgent.EXPECT().ReadSlot("f9").Return(cert, nil).Times(1)
				return yubicoAgent, serialPath
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent, p := tt.agent(t)
			f9CertsDir := filepath.Dir(p)
			a := &authn{
				agent:      agent,
				f9CertsDir: f9CertsDir,
			}
			if err := a.Authenticate(nil); (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
