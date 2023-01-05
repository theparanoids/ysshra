// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	"github.com/theparanoids/ysshra/keyid"
	keyutil "github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
)

// SlotAgent wraps the yubiagent and stores the information of a key slot in the agent.
type SlotAgent struct {
	yubiAgent YubiAgent
	code      string                                // the code of the key slot, e.g. "9a", "9e"
	public    ssh.PublicKey                         // the public key stored in the key slot
	attest    *x509.Certificate                     // the attestation certificate of the key slot
	policy    keyid.TouchPolicy                     // the touch policy of the key slot
	csrs      []*proto.SSHCertificateSigningRequest // the certificates signing requests that are backed by the key slot
}

// NewSlotAgent returns the key slot agent.
func NewSlotAgent(yubiAgent YubiAgent, code string) (*SlotAgent, error) {
	attestationCert, err := yubiAgent.AttestSlot(code)
	if err != nil {
		return nil, err
	}
	// Due to Infineon Technologies' RSA key generation issue, we do not support RSA
	// certificates generated by YubiKeys with firmware between 4.2.6-4.3.4.
	// Ref: https://www.yubico.com/support/security-advisories/ysa-2017-01/
	if attestationCert.PublicKeyAlgorithm == x509.RSA && isAffectedVersion(attestationCert.Extensions) {
		return nil, fmt.Errorf("found RSA certificate generated by YubiKey with firmware 4.2.6-4.3.4")
	}

	publicKey, err := ssh.NewPublicKey(attestationCert.PublicKey)
	if err != nil {
		return nil, err
	}
	if validateSSHPublicKeyAlgo(publicKey) {
		return nil, fmt.Errorf("unsupported certificate type in the key slot: %s", code)
	}

	touchPolicy := getTouchPolicy(attestationCert)

	return &SlotAgent{
		code:      code,
		public:    publicKey,
		attest:    attestationCert,
		policy:    touchPolicy,
		yubiAgent: yubiAgent,
	}, nil
}

// NewSlotAgentWithAttrs returns a new slot agent with attribute values.
func NewSlotAgentWithAttrs(yubiAgent YubiAgent, code string, public ssh.PublicKey,
	attest *x509.Certificate, policy keyid.TouchPolicy) *SlotAgent {
	return &SlotAgent{
		yubiAgent: yubiAgent,
		code:      code,
		public:    public,
		attest:    attest,
		policy:    policy,
	}
}

// RegisterCSR registers the given certificate signing request for the key slot.
func (s *SlotAgent) RegisterCSR(csr *proto.SSHCertificateSigningRequest) {
	s.csrs = append(s.csrs, csr)
}

// RegisterCSRs registers multiple certificate signing request for the key slot.
func (s *SlotAgent) RegisterCSRs(csrs []*proto.SSHCertificateSigningRequest) {
	for _, csr := range csrs {
		s.RegisterCSR(csr)
	}
}

// CSRs returns the registered CSRs.
func (s *SlotAgent) CSRs() []*proto.SSHCertificateSigningRequest {
	return s.csrs
}

// AddCertsToAgent adds certificates to the agent.
func (s *SlotAgent) AddCertsToAgent(certs []ssh.PublicKey, comments []string) error {
	for i, c := range certs {
		cert, err := keyutil.CastSSHPublicKeyToCertificate(c)
		if err != nil {
			continue
		}
		err = s.yubiAgent.AddHardCert(cert, comments[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// PublicKey returns the public key of the key slot.
func (s *SlotAgent) PublicKey() ssh.PublicKey {
	return s.public
}

// TouchPolicy returns the touch policy of the key slot.
func (s *SlotAgent) TouchPolicy() keyid.TouchPolicy {
	return s.policy
}

// Serial returns the serial number of the yubikey.
func (s *SlotAgent) Serial() (string, error) {
	return yubiattest.ModHex(s.attest)
}

// SlotCode returns the code number of the key slot.
func (s *SlotAgent) SlotCode() string {
	return s.code
}

// AttestCert returns the attest cert of the key slot.
func (s *SlotAgent) AttestCert() *x509.Certificate {
	return s.attest
}

// Agent returns the yubiagent.
func (s *SlotAgent) Agent() YubiAgent {
	return s.yubiAgent
}

// getTouchPolicy returns the touch policy coded in the given attestation certificate
func getTouchPolicy(attestCert *x509.Certificate) keyid.TouchPolicy {
	var touch = keyid.DefaultTouch
	if attestCert == nil {
		return touch
	}
	for _, ext := range attestCert.Extensions {
		// NOTE: The following id is the touch policy stored in attestation certificate.
		//       Refer: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
		if ext.Id.String() == "1.3.6.1.4.1.41482.3.8" {
			touch = keyid.TouchPolicy(ext.Value[1])
		}
	}
	return touch
}

// YubiKeys with firmaware version 4.2.6 - 4.3.4 are only affected by
// Infineon RSA key generation issue
func isAffectedVersion(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.String() == "1.3.6.1.4.1.41482.3.3" {
			version := int(ext.Value[0])*100 + int(ext.Value[1])*10 + int(ext.Value[2])
			if version >= 426 && version <= 434 {
				log.Printf("affected firmware detected, %v", version)
				return true
			}
		}
	}
	return false
}

// validateSSHPublicKeyAlgo validates certs created in 9e and 9a slots.
func validateSSHPublicKeyAlgo(pub crypto.PublicKey) bool {
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		switch pk.Size() * 8 {
		case 2048:
			return true
		default:
			return false
		}
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256(), elliptic.P384():
			return true
		default:
			return false
		}
	// ed25519 is non-supported key algo for now.
	default:
		return false
	}
}
