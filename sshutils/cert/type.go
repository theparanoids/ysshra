// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"go.vzbuilders.com/peng/sshra-oss/keyid"
)

// CriticalOptionTouchlessSudoHosts is a critical option in the cert to set a list of hosts with both touchless ssh and touchless sudo credentials valid.
const CriticalOptionTouchlessSudoHosts = "touchless-sudo-hosts"

// Type indicates the type of ssh cert provisioned by SSHRA.
// Steps required to define a new kind of certificate, in that order:
// 1. Add the new CertType below
// 2. Update GetType() function to ensure we have a unique way to identify
// a certificate. As far as possible, it should rely *only* on keyid in the certificate
// to uniquely identify the certificate type
// 3. Rebuild client packages and ship them out
// 4. Make the changes on production to start issuing the certificates of new kind
type Type int

const (
	// UnknownCertType indicates that the type of certificate is unknown.
	UnknownCertType Type = iota
	// TouchSudoCert is the certificate which requires a touch for SSH and SUDO authentication.
	// TouchSudoCert's private key is backed in a smartcard.
	TouchSudoCert
	// TouchlessCert is the certificate which does not require a touch for SSH authentication.
	// TouchlessCert's private key is backed in a smartcard.
	// Note: TouchlessCert can be used for SUDO authentication by defining a touchless cert filter in PAM SSHCA.
	TouchlessCert
	// TouchlessSudoCert is the certificate which does not require a touch for SSH or SUDO authentication on a set of hosts.
	// TouchlessSudoCert's private key is backed in a smartcard.
	TouchlessSudoCert
	// FirefighterCert is a touch certificate with longer validity for emergency use.
	// FirefighterCert's private key is backed in a smartcard.
	FirefighterCert
	// NonceCert is the certificate for one time authentication. It is used as a certificate based token.
	NonceCert
	_ // deprecated
	// TouchlessInAgentCert is the certificate which does not require a touch for SSH authentication.
	// TouchlessInAgentCert's private key is backed in SSH-agent.
	// Note: TouchlessInAgentCert can be used for SUDO authentication by defining a customized cert filter in PAM SSHCA.
	TouchlessInAgentCert
	// TouchlessSudoInAgentCert is the certificate which does not require a touch for SUDO authentication on a set of hosts.
	// TouchlessSudoInAgentCert's private key is backed in SSH-agent.
	TouchlessSudoInAgentCert
)

// TypeLabel is the mapping from cert type to label.
var TypeLabel = map[Type]string{
	TouchSudoCert:            "TouchSudo",
	TouchlessCert:            "Touchless",
	TouchlessSudoCert:        "TouchlessSudo",
	FirefighterCert:          "FireFighterSudo",
	NonceCert:                "Nonce",
	TouchlessInAgentCert:     "TouchlessInAgent",
	TouchlessSudoInAgentCert: "TouchlessSudoInAgent",
}

// GetType returns the certificate type based on different keyid and certificate options
// set by sshra gensign.
func GetType(cert *ssh.Certificate) Type {
	certType := UnknownCertType
	if cert == nil {
		return certType
	}
	k, err := keyid.Unmarshal(cert.KeyId)
	if err != nil {
		return certType
	}
	switch {
	case k.IsNonce:
		certType = NonceCert
	case k.IsFirefighter && k.IsHWKey:
		certType = FirefighterCert
	case k.IsFirefighter && !k.IsHWKey:
		certType = TouchlessInAgentCert
		if cert.CriticalOptions != nil && cert.CriticalOptions[CriticalOptionTouchlessSudoHosts] != "" {
			certType = TouchlessSudoInAgentCert
		}
	case k.TouchPolicy == keyid.CachedTouch || k.TouchPolicy == keyid.AlwaysTouch:
		certType = TouchSudoCert
	case k.TouchPolicy == keyid.NeverTouch:
		certType = TouchlessCert
		if cert.CriticalOptions != nil && cert.CriticalOptions[CriticalOptionTouchlessSudoHosts] != "" {
			certType = TouchlessSudoCert
		}
	}
	return certType
}

// Label returns the label to be attached to the certificate, based on keyid and certificate options.
func Label(cert *ssh.Certificate) (string, error) {
	certType := GetType(cert)
	if certType == UnknownCertType {
		return "", errors.New("invalid certificate type")
	}
	label, ok := TypeLabel[certType]
	if !ok {
		return "", errors.New("unknown certificate")
	}
	k, err := keyid.Unmarshal(cert.KeyId)
	if err != nil {
		return "", fmt.Errorf("keyid.Unmarshal failed: err: %v", err)
	}
	label += "SSH-" + k.TransID
	return label, nil
}

func (c Type) String() string {
	return TypeLabel[c]
}
