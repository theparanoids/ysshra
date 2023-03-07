package key

import "testing"

func TestGetSSHKeyAlgo(t *testing.T) {
	t.Parallel()
	table := map[string]struct {
		keyType     string
		wantKeyAlgo PublicKeyAlgo
		wantErr     bool
	}{
		"rsa2048 key":  {"RSA2048", RSA2048, false},
		"ec p-256 key": {"ECCP256", ECDSAsecp256r1, false},
		"ec p-384 key": {"ECCP384", ECDSAsecp384r1, false},
		"ec p-521 key": {"ECCP521", ECDSAsecp521r1, false},
		"invalid key":  {"INVALID", RSA2048, true},
		"empty key":    {"", RSA2048, true},
	}
	for label, tt := range table {
		got, err := GetSSHKeyAlgo(tt.keyType)
		if tt.wantErr && err == nil {
			t.Errorf("%s, go nil, want err", label)
		}
		if tt.wantKeyAlgo != got {
			t.Errorf("%s, got %v, want %v", label, got, tt.wantKeyAlgo)
		}
	}
}
