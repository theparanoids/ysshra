// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"crypto/x509"
	"reflect"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// publicKeyAlgoName is the mapping from string to x509.PublicKeyAlgorithm.
// Declare all the keys in lower case to support case-insensitive lookup.
var publicKeyAlgoName = map[string]x509.PublicKeyAlgorithm{
	"default": x509.UnknownPublicKeyAlgorithm,
	"unknown": x509.UnknownPublicKeyAlgorithm,
	"rsa":     x509.RSA,
	"dsa":     x509.DSA,
	"ecdsa":   x509.ECDSA,
	"ed25519": x509.Ed25519,
}

// StringToX509PublicKeyAlgo returns a DecodeHookFunc that converts
// string to x509.PublicKeyAlgorithm.
func StringToX509PublicKeyAlgo() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t != reflect.TypeOf(x509.UnknownPublicKeyAlgorithm) {
			return data, nil
		}

		// Case 1: the algorithm is specified by its name.
		algo, ok := publicKeyAlgoName[strings.ToLower(data.(string))]
		if ok {
			return algo, nil
		}

		// Case 2: the algorithm is specified by enum.
		u, err := strconv.ParseUint(data.(string), 10, 0)
		if err != nil {
			return nil, err
		}
		return x509.PublicKeyAlgorithm(u), nil
	}
}
