// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package tlsutils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/theparanoids/crypki/certreload"
)

// TLSClientConfiguration returns the TLS configuration for a client.
func TLSClientConfiguration(certPath, keyPath string, caCertPaths []string) (*tls.Config, error) {
	reloader, err := certreload.NewCertReloader(
		certreload.CertReloadConfig{
			CertKeyGetter: func() ([]byte, []byte, error) {
				certPEMBlock, err := os.ReadFile(certPath)
				if err != nil {
					return nil, nil, err
				}
				keyPEMBlock, err := os.ReadFile(keyPath)
				if err != nil {
					return nil, nil, err
				}
				return certPEMBlock, keyPEMBlock, nil
			},
			PollInterval: 6 * time.Hour,
		})
	if err != nil {
		return nil, fmt.Errorf("unable to get client cert reloader: %s", err)
	}

	// Load TLS server CA certs.
	caCertPool := x509.NewCertPool()
	for _, caCertFile := range caCertPaths {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf(`failed to read TLS server CA certificate %q, err:%v`, caCertFile, err)
		}
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf(`failed to parse certificate %q`, caCertFile)
		}
	}

	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,           // require TLS 1.2 or higher
		NextProtos:             []string{"h2", "http/1.1"}, // prefer HTTP/2 explicitly
		CipherSuites:           standardCipherSuites(),
		SessionTicketsDisabled: true, // Don't allow session resumption
		GetClientCertificate:   reloader.GetClientCertificate,
		RootCAs:                caCertPool,
	}

	return cfg, nil
}

func standardCipherSuites() []uint16 {
	return []uint16{
		// TLS 1.3 cipher suites.
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,

		// TLS 1.2 cipher suites.
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		// Go stdlib currently does not support AES CCM cipher suite - https://github.com/golang/go/issues/27484
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
}
