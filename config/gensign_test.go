package config

import (
	"os"
	"path"
	"reflect"
	"testing"
)

func TestNewGensignConfig(t *testing.T) {
	tests := []struct {
		name    string
		getPath func(t *testing.T) string
		want    *GensignConfig
		wantErr bool
	}{
		{
			name: "happy path",
			getPath: func(t *testing.T) string {
				configStr := `
					{
						"keyid_version": 1,
						"sshca_failure_dir" : "/dev/shm/sshcafailures/",
						"sshca_failure_timeout" : 3600,
						"sshca_failure_retry" : 5,
						"handlers": {
							"Regular": {
								"enable": true,
								"public_key_dir": "/etc/ssh/sshra/pubkey"
							}
						},
						"signer": {
							"tls_client_key_file": "path_to_tls_client.key",
							"tls_client_cert_file": "path_to_tls_client.crt"
						}
					}`
				configPath := path.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(configPath, []byte(configStr), 0644); err != nil {
					t.Fatalf("failed to write config file, err: %v", err)
				}
				return configPath
			},
			want: &GensignConfig{
				KeyIDVersion:        1,
				SSHCAFailureDir:     "/dev/shm/sshcafailures/",
				SSHCAFailureTimeout: 3600,
				SSHCAFailureRetry:   5,
				HandlerConfig: map[string]handlerConfMap{
					"Regular": {
						"enable":         true,
						"public_key_dir": "/etc/ssh/sshra/pubkey",
					},
				},
				SignerConfig: map[string]interface{}{
					"tls_client_key_file":  "path_to_tls_client.key",
					"tls_client_cert_file": "path_to_tls_client.crt",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGensignConfig(tt.getPath(t))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGensignConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewGensignConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGensignConfig_ExtractHandlerConf(t *testing.T) {
	type exampleHandlerConf struct {
		Enable     bool
		PubKeyPath string `mapstructure:"pub_key_path"`
		Text       string
		Number     int
	}

	tests := []struct {
		name            string
		handlerName     string
		gensignConf     *GensignConfig
		wantHandlerConf *exampleHandlerConf
		wantErr         bool
	}{
		{
			name:        "happy path",
			handlerName: "ExampleHandler",
			gensignConf: &GensignConfig{
				HandlerConfig: map[string]handlerConfMap{
					"ExampleHandler": {
						"enable":       true,
						"pub_key_path": "/etc/ssh/pub_key",
						"text":         "some text",
						"number":       10,
					},
				},
			},
			wantHandlerConf: &exampleHandlerConf{
				Enable:     true,
				PubKeyPath: "/etc/ssh/pub_key",
				Text:       "some text",
				Number:     10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := new(exampleHandlerConf)
			err := tt.gensignConf.ExtractHandlerConf(tt.handlerName, got)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractHandlerConf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.wantHandlerConf) {
				t.Errorf("ExtractHandlerConf() got handler conf = %v, want %v", got, tt.wantHandlerConf)
			}
		})
	}
}
