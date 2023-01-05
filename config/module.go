// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

// DecodeModuleConf decodes module configuration.
func DecodeModuleConf(undecodedConf interface{}, modConf interface{}) error {
	config := &mapstructure.DecoderConfig{
		DecodeHook: StringToX509PublicKeyAlgo(),
		Metadata:   nil,
		Result:     modConf,
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return fmt.Errorf("failed to initialize decoder, %v", err)
	}
	err = decoder.Decode(undecodedConf)
	if err != nil {
		return fmt.Errorf("failed to decode config, %v", err)
	}
	return nil
}
