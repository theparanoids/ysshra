package crypki

import (
	"reflect"
	"testing"
	"time"
)

func Test_decodeSignerConfig(t *testing.T) {
	tests := []struct {
		name         string
		signerConfig map[string]interface{}
		want         SignerConfig
		wantErr      bool
	}{
		{
			name: "happy path",
			signerConfig: map[string]interface{}{
				"tls_client_key_file":  "tls_client_key_file",
				"tls_client_cert_file": "tls_client_cert_file",
				"per_try_timeout":      "5s",
			},
			want: SignerConfig{
				TLSClientKeyFile:  "tls_client_key_file",
				TLSClientCertFile: "tls_client_cert_file",
				PerTryTimeout:     5 * time.Second,
			},
		},
		{
			name: "happy path 2",
			signerConfig: map[string]interface{}{
				"tls_client_key_file":  "tls_client_key_file",
				"tls_client_cert_file": "tls_client_cert_file",
				"per_try_timeout":      "6h5s",
			},
			want: SignerConfig{
				TLSClientKeyFile:  "tls_client_key_file",
				TLSClientCertFile: "tls_client_cert_file",
				PerTryTimeout:     6*time.Hour + 5*time.Second,
			},
		},
		{
			name: "invalid timeout",
			signerConfig: map[string]interface{}{
				"tls_client_key_file":  "tls_client_key_file",
				"tls_client_cert_file": "tls_client_cert_file",
				"per_try_timeout":      "asdfasdfasdf",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSignerConfig(tt.signerConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeSignerConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeSignerConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}
