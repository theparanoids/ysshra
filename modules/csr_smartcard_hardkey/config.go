// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr_smartcard_hardkey

type config struct {
	// Slot is the slot number inside a yubikey.
	Slot string `mapstructure:"slot"`
	// CertValiditySec is the validity period of the certificate in seconds.
	CertValiditySec uint64 `mapstructure:"cert_validity_sec" default:"43200"`
	// IsFirefighter indicates whether the certificate is for emergency situation.
	IsFirefighter bool `mapstructure:"is_firefighter"`
	// TouchPolicy indicates the touch policy of the certificate.
	TouchPolicy int `mapstructure:"touch_policy"`
	// PrincipalsTpl is the template to generate template list.
	PrincipalsTpl string `mapstructure:"principals_tpl"`
}
