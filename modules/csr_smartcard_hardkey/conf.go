// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr_smartcard_hardkey

type conf struct {
	Slot            string `mapstructure:"slot"`
	CertValiditySec uint64 `mapstructure:"cert_validity_sec" default:"43200"`
	IsFirefighter   bool   `mapstructure:"is_firefighter"`
	TouchPolicy     int    `mapstructure:"touch_policy"`
	PrincipalsTpl   string `mapstructure:"principals_tpl"`
}
