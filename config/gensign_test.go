// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"crypto/x509"
	"os"
	"path"
	"reflect"
	"testing"
	"time"
)

func TestNewGensignConfig(t *testing.T) {
	t.Parallel()
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
						"public_key_dir": "/etc/ssh/sshra/pubkey",
					},
				},
				SignerConfig: map[string]interface{}{
					"tls_client_key_file":  "path_to_tls_client.key",
					"tls_client_cert_file": "path_to_tls_client.crt",
				},
				RequestTimeout: 60 * time.Second,
			},
		},
		{
			name: "explicitly set gensign timeout",
			getPath: func(t *testing.T) string {
				configStr := `
					{
						"keyid_version": 1,
						"sshca_failure_dir" : "/dev/shm/sshcafailures/",
						"sshca_failure_timeout" : 3600,
						"sshca_failure_retry" : 5,
						"handlers": {
							"Regular": {
								"public_key_dir": "/etc/ssh/sshra/pubkey"
							}
						},
						"signer": {
							"tls_client_key_file": "path_to_tls_client.key",
							"tls_client_cert_file": "path_to_tls_client.crt"
						},
						"request_timeout": 30
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
						"public_key_dir": "/etc/ssh/sshra/pubkey",
					},
				},
				SignerConfig: map[string]interface{}{
					"tls_client_key_file":  "path_to_tls_client.key",
					"tls_client_cert_file": "path_to_tls_client.crt",
				},
				RequestTimeout: 30 * time.Second,
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
	t.Parallel()
	type exampleHandlerConf struct {
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
						"pub_key_path": "/etc/ssh/pub_key",
						"text":         "some text",
						"number":       10,
					},
				},
			},
			wantHandlerConf: &exampleHandlerConf{
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

func TestGensignConfig_ExtractHandlerConf_X509PublicKeyAlgo(t *testing.T) {
	t.Parallel()
	type exampleHandlerConf struct {
		KeyIdentifiers map[x509.PublicKeyAlgorithm]string `mapstructure:"key_identifiers"`
	}
	tests := []struct {
		name            string
		handlerName     string
		getPath         func(t *testing.T) string
		wantHandlerConf *exampleHandlerConf
		wantErr         bool
	}{
		{
			name:        "happy path",
			handlerName: "example_handler",
			getPath: func(t *testing.T) string {
				configStr := `
					{
						"keyid_version": 1,
						"sshca_failure_dir" : "/dev/shm/sshcafailures/",
						"sshca_failure_timeout" : 3600,
						"sshca_failure_retry" : 5,
						"handlers": {
							"example_handler": {
								"key_identifiers": {
									"default": "key-default",
									"rsa": "key-rsa"
								}
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
			wantHandlerConf: &exampleHandlerConf{
				KeyIdentifiers: map[x509.PublicKeyAlgorithm]string{
					x509.UnknownPublicKeyAlgorithm: "key-default",
					x509.RSA:                       "key-rsa",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gensignConf, err := NewGensignConfig(tt.getPath(t))
			if err != nil {
				t.Fatal(err)
			}
			got := new(exampleHandlerConf)
			err = gensignConf.ExtractHandlerConf(tt.handlerName, got)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractHandlerConf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.wantHandlerConf) {
				t.Errorf("ExtractHandlerConf() got = %v, want %v", got, tt.wantHandlerConf)
			}
		})
	}
}
