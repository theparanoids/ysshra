// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package utils

import (
	"os"
	"testing"
)

func TestParsePEMCertificate(t *testing.T) {
	// Empty File.
	_, err := ParsePEMCertificate([]byte(""))
	if err == nil || err.Error() != "certificate not found" {
		t.Errorf("expect error \"certificate not found\", got %v", err)
	}

	// Regular Certificates,
	data, err := os.ReadFile("./testdata/pem.cert")
	if err != nil {
		t.Fatalf("cannot read file: %v", err)
	}
	_, err = ParsePEMCertificate(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Broken Certificates.
	data, err = os.ReadFile("./testdata/pemBROKEN.cert")
	if err != nil {
		t.Fatalf("cannot read file: %v", err)
	}
	_, err = ParsePEMCertificate(data)
	if err == nil {
		t.Errorf("expect an error")
	}
}

func TestParsePEMCertificates(t *testing.T) {
	// Empty File.
	certs, err := ParsePEMCertificates([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expect 0 certificates, got %v", len(certs))
	}

	// Regular Certificates.
	data, err := os.ReadFile("./testdata/pem.cert")
	if err != nil {
		t.Fatalf("cannot read file: %v", err)
	}
	certs, err = ParsePEMCertificates(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expect 2 certificates, got %v", len(certs))
	}

	// Broken Certificates.
	data, err = os.ReadFile("./testdata/pemBROKEN.cert")
	if err != nil {
		t.Fatalf("cannot read file: %v", err)
	}
	_, err = ParsePEMCertificates(data)
	if err == nil {
		t.Errorf("expect an error")
	}
}
