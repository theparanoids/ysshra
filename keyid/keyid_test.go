// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package keyid

import (
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
	t.Parallel()
	testcases := map[string]struct {
		output      string
		expectError bool
		kid         *KeyID
	}{
		"valid": {
			output:      `{"prins":["dummy"],"transID":"22dde224","reqUser":"dummy","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"usage":0,"touchPolicy":3,"ver":1}`,
			expectError: false,
			kid: &KeyID{
				Principals:    []string{"dummy"},
				TransID:       "22dde224",
				ReqUser:       "dummy",
				ReqIP:         "1.1.1.1",
				ReqHost:       "dummyHost",
				IsFirefighter: false,
				IsNonce:       false,
				IsHWKey:       true,
				IsHeadless:    false,
				Usage:         AllUsage,
				TouchPolicy:   CachedTouch,
				Version:       1,
			},
		},
		"valid keyid nonce": {
			output:      `{"prins":["dummy"],"transID":"22dde224","reqUser":"dummy","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":true,"usage":0,"touchPolicy":1,"ver":1}`,
			expectError: false,
			kid: &KeyID{
				Principals:    []string{"dummy"},
				TransID:       "22dde224",
				ReqUser:       "dummy",
				ReqIP:         "1.1.1.1",
				ReqHost:       "dummyHost",
				IsFirefighter: false,
				IsNonce:       true,
				IsHWKey:       true,
				IsHeadless:    false,
				Usage:         AllUsage,
				TouchPolicy:   NeverTouch,
				Version:       1,
			},
		},
		"invalid unsupported version": {
			output:      "",
			expectError: true,
			kid: &KeyID{
				Version: 2,
			},
		},
		"invalid fail V1 sanity check": {
			output:      "",
			expectError: true,
			kid: &KeyID{
				Version:       1,
				IsHeadless:    true,
				IsFirefighter: true,
			},
		},
		"invalid fail V1 nonce sanity check": {
			output:      "",
			expectError: true,
			kid: &KeyID{
				Version:       1,
				IsNonce:       true,
				IsFirefighter: true,
			},
		},
	}
	for k, tt := range testcases {
		tt := tt // capture range variable - see https://blog.golang.org/subtests
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			kid, err := tt.kid.Marshal()
			if err != nil {
				if !tt.expectError {
					t.Errorf("unexpected err: %v", err)
				}
				return
			}
			if tt.expectError {
				t.Error("expected error, got none")
			}
			if !reflect.DeepEqual(kid, tt.output) {
				t.Errorf("kid mismatch, got \n%+v\n, want \n%+v\n", kid, tt.output)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	t.Parallel()
	testcases := map[string]struct {
		input       string
		expectError bool
		kid         *KeyID
	}{
		"valid": {
			input:       `{"prins":["dummy"],"transID":"22dde224","reqUser":"dummy","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"usage":0,"touchPolicy":3,"ver":1}`,
			expectError: false,
			kid: &KeyID{
				Principals:    []string{"dummy"},
				TransID:       "22dde224",
				ReqUser:       "dummy",
				ReqIP:         "1.1.1.1",
				ReqHost:       "dummyHost",
				IsFirefighter: false,
				IsNonce:       false,
				IsHWKey:       true,
				IsHeadless:    false,
				Usage:         AllUsage,
				TouchPolicy:   CachedTouch,
				Version:       1,
			},
		},
		"valid multiple principals": {
			input:       `{"prins":["dummy", "hchen12"],"transID":"22dde224","reqUser":"dummy","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"usage":0,"touchPolicy":3,"ver":1}`,
			expectError: false,
			kid: &KeyID{
				Principals:    []string{"dummy", "hchen12"},
				TransID:       "22dde224",
				ReqUser:       "dummy",
				ReqIP:         "1.1.1.1",
				ReqHost:       "dummyHost",
				IsFirefighter: false,
				IsNonce:       false,
				IsHWKey:       true,
				IsHeadless:    false,
				Usage:         AllUsage,
				TouchPolicy:   CachedTouch,
				Version:       1,
			},
		},
		"valid value is key": {
			input:       `{"prins":["dummy"],"transID":"22dde224","reqUser":"transID","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"usage":1,"touchPolicy":3,"ver":1}`,
			expectError: false,
			kid: &KeyID{
				Principals:    []string{"dummy"},
				TransID:       "22dde224",
				ReqUser:       "transID",
				ReqIP:         "1.1.1.1",
				ReqHost:       "dummyHost",
				IsFirefighter: false,
				IsNonce:       false,
				IsHWKey:       true,
				IsHeadless:    false,
				Usage:         SSHOnlyUsage,
				TouchPolicy:   CachedTouch,
				Version:       1,
			},
		},
		"invalid not json object": {
			"prins=dummy,user1, reqU=dummy, transID=22dde224, isHWKey=123, touchPolicy=3, isFirefighter=false, isHeadless=false, ver=1",
			true,
			nil,
		},
		"invalid unsupported version": {
			`{"prins":["dummy"],"transID":"22dde224","reqUser":"dummy","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"touchPolicy":3,"ver":2}`,
			true,
			nil,
		},
		"invalid missing key (transID)": {
			`{"prins":["dummy"],"reqUser":"dummy","reqIP":"1.1.1.1","reqHost":"dummyHost","isFirefighter":false,"isHWKey":true,"isHeadless":false,"touchPolicy":3,"ver":1}`,
			true,
			nil,
		},
	}

	for k, tt := range testcases {
		tt := tt // capture range variable - see https://blog.golang.org/subtests
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			kid, err := Unmarshal(tt.input)
			if err != nil {
				if !tt.expectError {
					t.Errorf("unexpected err: %v", err)
				}
				return
			}
			if tt.expectError {
				t.Error("expected error, got none")
			}
			if !reflect.DeepEqual(kid, tt.kid) {
				t.Errorf("kid mismatch, got \n%+v\n, want \n%+v\n", kid, tt.kid)
			}
		})
	}
}

func TestSanityCheckerHeadless(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		kid         *KeyID
		expectError bool
	}{
		{
			name: "not headless",
			kid: &KeyID{
				IsHeadless: false,
			},
			expectError: false,
		},
		{
			name: "hwkey",
			kid: &KeyID{
				IsHeadless: true,
				IsHWKey:    true,
			},
			expectError: true,
		},
		{
			name: "firefighter",
			kid: &KeyID{
				IsHeadless:    true,
				IsFirefighter: true,
			},
			expectError: true,
		},
		{
			name: "valid touch",
			kid: &KeyID{
				IsHeadless:  true,
				TouchPolicy: NeverTouch,
			},
			expectError: false,
		},
		{
			name: "invalid touch",
			kid: &KeyID{
				IsHeadless:  true,
				TouchPolicy: AlwaysTouch,
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := sanityCheckerHeadless(tc.kid)
			if tc.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSanityCheckerNonce(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		kid         *KeyID
		expectError bool
	}{
		{
			name: "not nonce",
			kid: &KeyID{
				IsNonce: false,
			},
			expectError: false,
		},
		{
			name: "firefighter",
			kid: &KeyID{
				IsNonce:       true,
				IsFirefighter: true,
			},
			expectError: true,
		},
		{
			name: "headless",
			kid: &KeyID{
				IsNonce:    true,
				IsHeadless: true,
			},
			expectError: true,
		},
		{
			name: "valid touch",
			kid: &KeyID{
				IsNonce:     true,
				TouchPolicy: NeverTouch,
			},
			expectError: false,
		},
		{
			name: "invalid touch",
			kid: &KeyID{
				IsNonce:     true,
				TouchPolicy: AlwaysTouch,
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := sanityCheckerNonce(tc.kid)
			if tc.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestKeyID_GetProperty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		keyID    *KeyID
		property string
		want     string
	}{
		{
			name:     "touchPolicy",
			keyID:    &KeyID{TouchPolicy: NeverTouch},
			property: "TouchPolicy",
			want:     "1",
		},
		{
			name:     "prins",
			keyID:    &KeyID{Principals: []string{"foo", "bar"}},
			property: "Principals",
			want:     "[foo bar]",
		},
		{
			name:     "undefined",
			keyID:    &KeyID{TouchPolicy: NeverTouch},
			property: "undefined",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.keyID.GetProperty(tt.name); got != tt.want {
				t.Errorf("GetPropertyByTag() = %v, want %v", got, tt.want)
			}
		})
	}
}
