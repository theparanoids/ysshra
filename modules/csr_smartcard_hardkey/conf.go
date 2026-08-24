package csr_smartcard_hardkey

type conf struct {
	IsFirefighter   bool   `mapstructure:"is_firefighter"`
	TouchPolicy     int    `mapstructure:"touch_policy"`
	Principals      string `mapstructure:"principals"`
	Slot            string `mapstructure:"slot"`
	CertValiditySec uint64 `mapstructure:"cert_validity_sec" default:"43200"`
}
