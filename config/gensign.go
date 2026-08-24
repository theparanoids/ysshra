// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mitchellh/mapstructure"
)

const (
	// 60 * time.Second
	requestTimeoutDefault = 60
)

type handlerConfMap map[string]interface{}

type SSHKeyConfig map[string]interface{}

// GensignConfig stores the configuration for gensign command.
type GensignConfig struct {
	// KeyIDVersion specifies the version of KeyID.
	KeyIDVersion uint16 `json:"keyid_version"`
	// SSHCAFailureDir stores the count of the failure requests to a CA.
	SSHCAFailureDir string `json:"sshca_failure_dir"`
	// SSHCAFailureRetry is the retry times limit.
	SSHCAFailureRetry int64 `json:"sshca_failure_retry"`
	// SSHCAFailureTimeout is the maximum time period to resend the request to CA (in second).
	SSHCAFailureTimeout int64 `json:"sshca_failure_timeout"`
	// HandlerConfig is the config mapping for all the csr handlers in following format:
	// "handlers": {
	//   "$HANDLER_NAME1": {
	//     "enable": true,
	//     "$KEY": $VALUE
	//   }
	//   "$HANDLER_NAME2": {
	//     "enable": true,
	//     "$KEY": $VALUE
	//   }
	// }
	HandlerConfig map[string]handlerConfMap `json:"handlers"`
	// SignerConfig is the mapping for signer configuration.
	SignerConfig map[string]interface{} `json:"signer"`
	// Timeout for gensign (in second).
	RequestTimeout time.Duration `json:"request_timeout"`
	// OTel is the configuration for connecting to OpenTelemetry collector.
	OTel OTelConfig `json:"otel"`
}

// OTelConfig stores the configuration for connecting to OpenTelemetry collector.
type OTelConfig struct {
	// Enabled indicates whether to enable OpenTelemetry.
	Enabled bool `json:"enabled"`
	// OTelCollectorEndpoint is the endpoint of the OpenTelemetry collector.
	OTELCollectorEndpoint string `json:"otel_collector_endpoint"`
	// ClientCertPath is the path to the client certificate.
	ClientCertPath string `json:"client_cert_path"`
	// ClientKeyPath is the path to the client key.
	ClientKeyPath string `json:"client_key_path"`
	// CACertPath is the path to the CA certificate.
	CACertPath string `json:"ca_cert_path"`
}

func (g *GensignConfig) populate() {
	if g.RequestTimeout <= 0 {
		g.RequestTimeout = requestTimeoutDefault
	}
	g.RequestTimeout = g.RequestTimeout * time.Second
}

// NewGensignConfig returns the gensign configuration loaded from the provided path.
func NewGensignConfig(path string) (*GensignConfig, error) {
	conf := new(GensignConfig)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, err
	}
	conf.populate()
	return conf, nil
}

// ExtractHandlerConf extracts handler config from GensignConfig by the given name.
func (g *GensignConfig) ExtractHandlerConf(name string, handlerConf interface{}) error {
	hConfMap, ok := g.HandlerConfig[name]
	if !ok {
		return fmt.Errorf("failed to find config for handler %q", name)
	}
	config := &mapstructure.DecoderConfig{
		DecodeHook: StringToX509PublicKeyAlgo(),
		Metadata:   nil,
		Result:     handlerConf,
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return fmt.Errorf("failed to initialize decoder %v", err)
	}
	err = decoder.Decode(hConfMap)
	if err != nil {
		return fmt.Errorf("failed to decode handler conf for %q, err:%v", name, err)
	}
	return nil
}
