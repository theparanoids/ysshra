// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_slot_attest

type config struct {
	// Slot is the slot number inside a yubikey.
	Slot string `mapstructure:"slot"`
	// PIVRootCA is the file path to the root CA of yubikey PIV (Personal Identity Verification).
	PIVRootCA string `mapstructure:"piv_root_ca"`
	// U2FRootCA is the file path to the root CA of yubikey U2F.
	U2FRootCA string `mapstructure:"u2f_root_ca"`
}
