// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiattest

import (
	"crypto/rsa"
	"testing"
)

const fakeYubicoPIVRootCA = "./testdata/Unittest_Root_CA.crt"

func TestInvalidAttest(t *testing.T) {
	t.Parallel()
	// get f9cert
	f9Cert, err := getCertificateFromFile("./testdata/Unittest_Attestation_f9.crt")
	if err != nil {
		t.Fatal(err)
	}

	crts := []string{
		"./testdata/Unittest_Authentication_9a.crt",          // signed by Unittest_Attestation_f9.crt
		"./testdata/Unittest_Authentication_9a_attest_2.crt", // not signed by Unittest_Attestation_f9.crt
	}

	attester, err := NewAttestor(fakeYubicoPIVRootCA, fakeYubicoPIVRootCA)
	if err != nil {
		t.Error(err)
	}

	for _, crt := range crts {
		attestCert, err2 := getCertificateFromFile(crt)
		if err2 != nil {
			t.Errorf("unexpected error, %v", err2)
			continue
		}
		err2 = attester.Attest(f9Cert, attestCert)
		if err2 != rsa.ErrVerification {
			t.Errorf("expected %v, got %v", rsa.ErrVerification, err2)
		}
	}

	// invalid f9Cert
	f9Cert, err = getCertificateFromFile("./testdata/Unittest_Authentication_9a.crt")
	if err != nil {
		t.Fatal(err)
	}
	attestCert, err := getCertificateFromFile("./testdata/Unittest_Authentication_9a_attest.crt")
	if err != nil {
		t.Fatal(err)
	}
	if err := attester.Attest(f9Cert, attestCert); err == nil {
		t.Error("expected error for certificate signed by unknown authority")
	}
}

func TestAttest(t *testing.T) {
	t.Parallel()
	f9Cert, err := getCertificateFromFile("./testdata/Unittest_Attestation_f9.crt")
	if err != nil {
		t.Fatal(err)
	}
	crts := []string{
		"./testdata/Unittest_Authentication_9a_attest.crt",
		"./testdata/Unittest_Authentication_9a_attest.crt",
	}

	attester, err := NewAttestor(fakeYubicoPIVRootCA, fakeYubicoPIVRootCA)
	if err != nil {
		t.Error(err)
	}

	for _, crt := range crts {
		attestCert, err := getCertificateFromFile(crt)
		if err != nil {
			t.Errorf("unexpected error, %v", err)
			continue
		}
		if err = attester.Attest(f9Cert, attestCert); err != nil {
			t.Error(err)
		}
	}
}
