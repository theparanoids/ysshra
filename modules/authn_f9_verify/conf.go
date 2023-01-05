// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_f9_verify

type conf struct {
	// F9CertsDir stores all the authorized f9 certificates.
	F9CertsDir string `mapstructure:"f9_certs_dir"`
}
