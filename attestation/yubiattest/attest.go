// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiattest

import (
	"crypto/x509"
	"fmt"
	"os"
)

// Attestor is the struct that performs attestation on a Yubikey.
type Attestor struct {
	// roots is a certificate pool, which should include YubicoPIVRootCA and YubicoU2FRootCA.
	roots *x509.CertPool
}

// NewAttestor returns a new Attestor struct.
func NewAttestor(pivRootCAPath string, u2fRootCAPath string) (*Attestor, error) {
	// Load Root certificates.
	yubicoPIVCA, err := os.ReadFile(pivRootCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pivRootCAPath, %v", err)
	}
	yubicoU2FCA, err := os.ReadFile(u2fRootCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read u2fRootCAPath, %v", err)
	}

	// Add YubiKey Root certificates into root certificate pool.
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(yubicoPIVCA); !ok {
		return nil, fmt.Errorf("cannot add root CA certificates")
	}
	if ok := roots.AppendCertsFromPEM(yubicoU2FCA); !ok {
		return nil, fmt.Errorf("cannot add root CA certificates")
	}
	return NewAttestorWithCAPool(roots), nil
}

// NewAttestorWithCAPool returns a new Attestor struct.
func NewAttestorWithCAPool(roots *x509.CertPool) *Attestor {
	return &Attestor{
		roots: roots,
	}
}

// Attest perform attestation on a YubiKey. It requires the attestation
// certificate (attestCert) in attested slot and the certificate in the
// attestation key slot. Attestation verifies such a certificate chain: YubicoPIVCA
// or YubicoU2FCA signs a f9 (attestation slot) cert, then the f9 cert signs attestCert.
// Note: the private key of an attestCert is backed in 9a or 9e key slot.
// Ref: https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
func (a *Attestor) Attest(f9Cert *x509.Certificate, attestCert *x509.Certificate) error {
	// Check whether f9 certificate is signed by YubiKey root certificate.
	if _, err := f9Cert.Verify(x509.VerifyOptions{Roots: a.roots}); err != nil {
		return err
	}
	// Check whether attestation certificate is signed by F9 certificate.
	return checkSignature(attestCert.SignatureAlgorithm, attestCert.RawTBSCertificate, attestCert.Signature, f9Cert.PublicKey)
}
