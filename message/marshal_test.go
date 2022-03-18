// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package message

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		attrs   *Attributes
		want    string
		wantErr bool
	}{
		{
			name: "simple test",
			attrs: &Attributes{
				IfVer:            7,
				Username:         "user",
				Hostname:         "host.com",
				SSHClientVersion: "8.1",
				HardKey:          true,
				Touch2SSH:        false,
				TouchlessSudo:    nil,
				CAPubKeyAlgo:     x509.PublicKeyAlgorithm(1),
				SignatureAlgo:    x509.SignatureAlgorithm(1),
				Exts: map[string]interface{}{
					"field1": "value1",
					"field2": float64(100),
				},
			},
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","caPubKeyAlgo":1,"signatureAlgo":1,"hardKey":true,"exts":{"field1":"value1","field2":100}}`,
		},
		{
			name: "TouchlessSudo empty",
			attrs: &Attributes{
				IfVer:            7,
				Username:         "user",
				Hostname:         "host.com",
				SSHClientVersion: "8.1",
				HardKey:          true,
				Touch2SSH:        false,
				TouchlessSudo: &TouchlessSudo{
					IsFirefighter: false,
					Hosts:         "",
					Time:          0,
				},
				Exts: map[string]interface{}{
					"field1": "value1",
					"field2": float64(100),
				},
			},
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","hardKey":true,"touchlessSudo":{},"exts":{"field1":"value1","field2":100}}`,
		},
		{
			name: "TouchlessSudo test case",
			attrs: &Attributes{
				IfVer:            7,
				Username:         "user",
				Hostname:         "host.com",
				SSHClientVersion: "8.1",
				HardKey:          true,
				Touch2SSH:        false,
				TouchlessSudo: &TouchlessSudo{
					IsFirefighter: true,
					Hosts:         "host01,host02,host03",
					Time:          int64(30), // 30 mins
				},
				Exts: map[string]interface{}{
					"field1": "value1",
					"field2": float64(100),
				},
			},
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","hardKey":true,"touchlessSudo":{"isFirefighter":true,"hosts":"host01,host02,host03","time":30},"exts":{"field1":"value1","field2":100}}`,
		},
		{
			name: "client version empty error",
			attrs: &Attributes{
				IfVer: 7,
			},
			wantErr: true,
		},
		{
			name: "user name empty error",
			attrs: &Attributes{
				IfVer:            7,
				SSHClientVersion: "8.1",
			},
			wantErr: true,
		},
		{
			name: "hostname empty error",
			attrs: &Attributes{
				IfVer:            7,
				SSHClientVersion: "8.1",
				Username:         "user",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.attrs.Marshal()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("%s: want error but got no error", tt.name)
				}
				return
			}
			if err != nil && !tt.wantErr {
				t.Fatalf("%s: want no error but got error: %v", tt.name, err)
			}
			if s != tt.want {
				t.Fatalf("expect: %#q, got: %#q", tt.want, s)
			}
			mm, err := Unmarshal(s)
			if err != nil {
				t.Fatal(err)
			}
			tt.attrs.populate()
			if !reflect.DeepEqual(tt.attrs, mm) {
				t.Fatalf("expect: %+v, got: %+v", tt.attrs, mm)
			}
		})
	}
}

func TestMarshalLegacy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		attrs *Attributes
		want  string
	}{
		{
			name: "simple path",
			attrs: &Attributes{
				IfVer:            6,
				Username:         "user",
				Hostname:         "host.com",
				SSHClientVersion: "8.1",
				HardKey:          true,
				Touch2SSH:        false,
				TouchlessSudo:    &TouchlessSudo{},
				Exts: map[string]interface{}{
					"HardKey":          "true",
					"IFVer":            "6",
					"SSHClientVersion": "8.1",
					"req":              "user@host.com",
				},
			},
			want: "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true",
		},
		{
			name: "touchless sudo",
			attrs: &Attributes{
				IfVer:            6,
				Username:         "user",
				Hostname:         "host.com",
				SSHClientVersion: "8.1",
				HardKey:          true,
				Touch2SSH:        false,
				TouchlessSudo: &TouchlessSudo{
					IsFirefighter: true,
					Hosts:         "host01,host02,host03",
					Time:          int64(30),
				},
				Exts: map[string]interface{}{
					"HardKey":            "true",
					"IFVer":              "6",
					"SSHClientVersion":   "8.1",
					"req":                "user@host.com",
					"TouchlessSudoHosts": "host01,host02,host03",
					"IsFirefighter":      "true",
					"TouchlessSudoTime":  "30",
				},
			},
			want: "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true IsFirefighter=true TouchlessSudoHosts=host01,host02,host03 TouchlessSudoTime=30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.attrs.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if s != tt.want {
				t.Fatalf("expect: %q, got: %q\n", tt.want, s)
			}
			mm, err := Unmarshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tt.attrs, mm) {
				t.Fatalf("expect: %+v, got: %+v", tt.attrs, mm)
			}
		})
	}
}

func TestUnmarshalHeadlesslLegacy(t *testing.T) {
	t.Parallel()
	args := "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true privKeyNeeded"
	got, err := Unmarshal(args)
	if err != nil {
		t.Fatalf("got err: %v\n", err)
	}
	want := &Attributes{
		IfVer:            6,
		Username:         "user",
		Hostname:         "host.com",
		SSHClientVersion: "8.1",
		HardKey:          true,
		Touch2SSH:        false,
		TouchlessSudo:    &TouchlessSudo{},
		Exts: map[string]interface{}{
			"HardKey":          "true",
			"IFVer":            "6",
			"SSHClientVersion": "8.1",
			"req":              "user@host.com",
			"privKeyNeeded":    "",
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("expect: %+v, got: %+v", want, got)
	}
}

func TestParseArgs(t *testing.T) {
	t.Parallel()
	originalCommand := `  key1=value1 key2=value2 key3="a=b" key4`
	expect := map[string]string{
		"key1": "value1", "key2": "value2", "key3": `"a=b"`, "key4": "",
	}
	args := parseAttrsLegacy(originalCommand)
	if !reflect.DeepEqual(args, expect) {
		t.Errorf("expect %v, got %v", expect, args)
	}
}

func TestAttributes_ExtendedAttrStr(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		attrs   *Attributes
		want    string
		wantErr bool
	}{
		{
			name: "happy path",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": "value",
				},
			},
			want: "value",
		},
		{
			name: "no key found",
			key:  "key_not_found",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": "value",
				},
			},
			wantErr: true,
		},
		{
			name: "not string type",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": 123,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.attrs.ExtendedAttrStr(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtendedAttrStr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtendedAttrStr() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttributes_ExtendedAttrBool(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		attrs   *Attributes
		want    bool
		wantErr bool
	}{
		{
			name: "happy path true",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": true,
				},
			},
			want: true,
		},
		{
			name: "happy path false",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": false,
				},
			},
			want: false,
		},
		{
			name: "no key found",
			key:  "key_not_found",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"not_found_key": "value",
				},
			},
			wantErr: true,
			want:    false,
		},
		{
			name: "string type true",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": "true",
				},
			},
			wantErr: false,
			want:    true,
		},
		{
			name: "string type false",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": "false",
				},
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "not string or bool type",
			key:  "key",
			attrs: &Attributes{
				Exts: map[string]interface{}{
					"key": 123,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.attrs.ExtendedAttrBool(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtendedAttrStr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtendedAttrStr() got = %v, want %v", got, tt.want)
			}
		})
	}
}
