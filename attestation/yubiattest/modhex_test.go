// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiattest

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"testing"
)

// getCertificateFromFile is a helper function which parses PEM encoded
// certificate from file and returns x509.Certificate for unit testing.
func getCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("failed to read file")
	}
	asn, _ := pem.Decode([]byte(data))
	cert, err := ParseCertificate(asn.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func TestModHex(t *testing.T) {
	cert, err := getCertificateFromFile("./testdata/fake_yubico_piv_attestation.crt")
	if err != nil {
		t.Fatal(err)
	}
	modhex, err := ModHex(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(modhex), []byte("cfcecdcb")) {
		t.Errorf("output doesn't match, expected %v, got %v", "ccfjdgrf", modhex)
	}

	cert, err = getCertificateFromFile("./testdata/Unittest_Authentication_9a.crt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ModHex(cert); err == nil {
		t.Error("expected error, cannot find serial number")
	}
}
