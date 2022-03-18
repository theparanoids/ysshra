// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/mitchellh/mapstructure"
)

func TestStringToX509PublicKeyAlgo(t *testing.T) {
	f := StringToX509PublicKeyAlgo()

	algoValue := reflect.ValueOf(x509.UnknownPublicKeyAlgorithm)
	strValue := reflect.ValueOf("")
	cases := []struct {
		f, t   reflect.Value
		result interface{}
		err    bool
	}{
		{reflect.ValueOf("default"), algoValue, x509.UnknownPublicKeyAlgorithm, false},
		{reflect.ValueOf("rsa"), algoValue, x509.RSA, false},
		{reflect.ValueOf("2"), algoValue, x509.DSA, false},
		{reflect.ValueOf("invalid"), algoValue, nil, true},
		{reflect.ValueOf("2"), strValue, "2", false},
	}

	for i, tc := range cases {
		actual, err := mapstructure.DecodeHookExec(f, tc.f, tc.t)
		if tc.err != (err != nil) {
			t.Fatalf("case %d: expected err %#v", i, tc.err)
		}
		if !reflect.DeepEqual(actual, tc.result) {
			t.Fatalf(
				"case %d: expected %#v, got %#v",
				i, tc.result, actual)
		}
	}
}
