// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

import (
	"crypto/x509"
	"time"

	"github.com/theparanoids/ysshura/agent/shimagent"
)

// YubiAgent is an interface that extends the functionality
// of the ShimAgent interface in agent/shimagent package,
// which also extends the native ssh agent.
type YubiAgent interface {
	shimagent.ShimAgent

	// ListSlots lists all the used slots in YubiKey.
	ListSlots() (slots []string, err error)

	// ReadSlot reads x509 certificate in PEM format from the specified slot.
	ReadSlot(slot string) (cert *x509.Certificate, err error)

	// AttestSlot signs the public key of the specified slot with the private key of "f9" slot and
	// returns the resulting attestation certificate in PEM format, which can be verified later on.
	// More details: https://developers.yubico.com/yubico-piv-tool/Attestation.html
	AttestSlot(slot string) (cert *x509.Certificate, err error)

	// AddSmartcardKey adds the specified smartcard to the agent.
	AddSmartcardKey(readerId string, pin []byte, lifetime time.Duration, confirmBeforeUse bool) error

	// RemoveSmartcardKey removes the specified smartcard from the agent.
	RemoveSmartcardKey(readerId string, pin []byte) error
}
