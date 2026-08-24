package config

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

func ExtractModuleConf(undecodedConf interface{}, modConf interface{}) error {
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
