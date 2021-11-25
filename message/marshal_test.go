package message

import (
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
				SignatureAlgo:    1,
				Exts: map[string]interface{}{
					"field1": "value1",
					"field2": float64(100),
				},
			},
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","signatureAlgo":1,"hardKey":true,"touch2SSH":false,"exts":{"field1":"value1","field2":100}}`,
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
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","signatureAlgo":0,"hardKey":true,"touch2SSH":false,"touchlessSudo":{"isFirefighter":true,"hosts":"host01,host02,host03","time":30},"exts":{"field1":"value1","field2":100}}`,
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
			if !reflect.DeepEqual(tt.attrs, mm) {
				t.Fatalf("expect: %+v, got: %+v", tt.attrs, mm)
			}
		})
	}
}

func TestMarshalLegacy(t *testing.T) {
	t.Parallel()
	a := &Attributes{
		IfVer:            6,
		Username:         "user",
		Hostname:         "host.com",
		SSHClientVersion: "8.1",
		HardKey:          true,
		Touch2SSH:        false,
		// TODO: test marshal and unmarshal of TouchlessSudo.
		TouchlessSudo: nil,
		Exts: map[string]interface{}{
			"HardKey":          "true",
			"IFVer":            "6",
			"SSHClientVersion": "8.1",
			"req":              "user@host.com",
		},
	}
	s, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true"
	if s != want {
		t.Fatalf("expect: %q, got: %q\n", want, s)
	}
	mm, err := Unmarshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, mm) {
		t.Fatalf("expect: %+v, got: %+v", a, mm)
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
