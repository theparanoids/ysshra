// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package utils

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/theparanoids/ysshra/attestation/yubiattest"
)

// ParsePEMCertificate parses one PEM certificate from data.
func ParsePEMCertificate(data []byte) (cert *x509.Certificate, err error) {
	certs, err := ParsePEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate not found")
	}
	return certs[0], nil
}

// ParsePEMCertificates parses all the PEM certificates from data.
func ParsePEMCertificates(data []byte) (certs []*x509.Certificate, err error) {
	for len(data) != 0 {
		ASN1, rest := pem.Decode(data)
		if ASN1 == nil {
			if len(bytes.TrimSpace(data)) == 0 {
				// Nothing left, free to return
				return certs, nil
			}
			return nil, fmt.Errorf("PEM: failed to decode %s", data)
		}
		data = rest

		// TODO: Change back to x509.ParseCertificate when all
		// the yubikeys have been upgraded to firmware 4.3.3.
		cert, err := yubiattest.ParseCertificate(ASN1.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
