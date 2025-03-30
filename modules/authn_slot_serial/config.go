// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_slot_serial

type config struct {
	// Slot is the slot number inside a yubikey.
	Slot string `mapstructure:"slot"`
	// YubikeyMappings is the mapping file that includes the mappings between a yubikey serial number and its belonger.
	YubikeyMappings string `mapstructure:"yubikey_mappings"`
}
