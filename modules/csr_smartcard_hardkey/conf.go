package csr_smartcard_hardkey

import "crypto/x509"

type conf struct {
	Tag           string `mapstructure:"keyid_ver"`
	KeyIDVer      uint16 `mapstructure:"keyid_ver"`
	IsFirefighter bool   `mapstructure:"is_firefighter"`
	IsHWKey       bool   `mapstructure:"is_hardware_key"`
	TouchPolicy   int    `mapstructure:"touch_policy"`
	Principals    string `mapstructure:"principals"`
	Slot          string `mapstructure:"slot"`
	// KeyIdentifiers is the mapping from CA public key algorithm to the key identifier configured in signer.
	KeyIdentifiers  map[x509.PublicKeyAlgorithm]string `mapstructure:"key_identifiers"`
	CertValiditySec uint64                             `mapstructure:"cert_validity_sec" default:"43200"`
}
