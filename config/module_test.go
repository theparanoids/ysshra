// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"reflect"
	"testing"
)

func TestExtractModuleConf(t *testing.T) {
	type exampleModConf struct {
		KeyString     string   `mapstructure:"key_string"`
		KeyInt        int      `mapstructure:"key_int"`
		KeyStringList []string `mapstructure:"key_string_list"`
	}

	tests := []struct {
		name          string
		undecodedConf interface{}
		wantConf      interface{}
		wantErr       bool
	}{
		{
			name: "happy path",
			undecodedConf: map[string]interface{}{
				"key_string":      "value-string",
				"key_int":         123,
				"key_string_list": []string{"value1", "value2"},
			},
			wantConf: map[string]interface{}{
				"key_string":      "value-string",
				"key_int":         123,
				"key_string_list": []string{"value1", "value2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &exampleModConf{}
			if err := DecodeModuleConf(tt.undecodedConf, &conf); (err != nil) != tt.wantErr {
				t.Errorf("DecodeModuleConf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if reflect.DeepEqual(conf, tt.wantConf) {
				t.Errorf("DecodeModuleConf() got = %v, want %v", conf, tt.wantConf)
			}
		})
	}
}
