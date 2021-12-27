package crypki

import (
	"time"

	"github.com/mitchellh/mapstructure"
)

const (
	perTryTimeoutDefault = 5 * time.Second
	retriesDefault       = 3
)

// SignerConfig contains the signer data from the config file.
type SignerConfig struct {
	// TLSClientKeyFile is the client key to authenticate requestor's identity at Crypki.
	TLSClientKeyFile string `mapstructure:"tls_client_key_file" validate:"required"`
	// TLSClientKeyFile is the client cert to authenticate requestor's identity at Crypki.
	TLSClientCertFile string `mapstructure:"tls_client_cert_file" validate:"required"`
	// TLSCACertFiles is the list of certification authority certs to verify Crypki server cert.
	TLSCACertFiles []string `mapstructure:"tls_ca_cert_files" validate:"required"`
	// CrypkiEndpoints is the endpoint list of the crypki servers.
	// It is recommended to put IPs or secondary DNS name into the list.
	// Signer tries to send the certificate request to the crypki server in the order of CrypkiEndpoints.
	// If any return success, the signed certificate will be returned to the caller.
	CrypkiEndpoints []string `mapstructure:"crypki_endpoints" validate:"required"`
	// CrypkiPort is the port number of the crypki servers.
	CrypkiPort uint `mapstructure:"crypki_port" validate:"required"`
	// Retries is the number of retry times to request certificate from a crypki server endpoint.
	Retries uint `mapstructure:"retries"`
	// PerTryTimeout is the RPC timeout per call.
	PerTryTimeout time.Duration `mapstructure:"per_try_timeout"`
}

func (s *SignerConfig) populate() {
	if s.Retries == 0 {
		s.Retries = retriesDefault
	}
	if s.PerTryTimeout <= 0 {
		s.PerTryTimeout = perTryTimeoutDefault
	}
}

func decodeSignerConfig(signerConfig map[string]interface{}) (SignerConfig, error) {
	var conf SignerConfig
	decoderConf := &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Metadata:   nil,
		Result:     &conf,
	}
	decoder, err := mapstructure.NewDecoder(decoderConf)
	if err != nil {
		return conf, err
	}
	if err := decoder.Decode(signerConfig); err != nil {
		return conf, err
	}
	return conf, nil
}
