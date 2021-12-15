package crypki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func tlsConfiguration(conf *SignerConfig) (*tls.Config, error) {
	// Load TLS client cert.
	cert, err := tls.LoadX509KeyPair(conf.TLSClientCertFile, conf.TLSClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf(`failed to load TLS client certificate, err: %v`, err)
	}

	// Load TLS server CA certs.
	caCertPool := x509.NewCertPool()
	for _, caCertFile := range conf.TLSCACertFiles {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf(`failed to read TLS server CA certificate %q, err:%v`, conf.TLSCACertFiles, err)
		}
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf(`failed to parse certificate %q`, conf.TLSCACertFiles)
		}
	}

	// Setup TLS configuration.
	tlsCfg := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		RootCAs:                caCertPool,
		MinVersion:             tls.VersionTLS12,           // require TLS 1.2 or higher
		NextProtos:             []string{"h2", "http/1.1"}, // prefer HTTP/2 explicitly
		SessionTicketsDisabled: true,                       // don't allow session resumption
	}

	tlsCfg.CipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	return tlsCfg, nil
}
