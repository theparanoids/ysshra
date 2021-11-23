package message

import (
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
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
				Github:           false,
				Nonce:            false,
				TouchlessSudo:    nil,
			},
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","hardKey":true,"touch2SSH":false,"github":false,"nonce":false,"touchlessSudo":null}`,
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
				Github:           false,
				Nonce:            false,
				TouchlessSudo: &TouchlessSudo{
					IsFirefighter:      true,
					TouchlessSudoHosts: "host01,host02,host03",
					TouchlessSudoTime:  30, // 30 mins
				},
			},
			want: `{"ifVer":7,"username":"user","hostname":"host.com","sshClientVersion":"8.1","hardKey":true,"touch2SSH":false,"github":false,"nonce":false,"touchlessSudo":{"isFirefighter":true,"touchlessSudoHosts":"host01,host02,host03","touchlessSudoTime":30}}`,
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
				Username:         "uer",
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
				t.Fatalf("expect: %q, got: %q", tt.want, s)
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
	a := &Attributes{
		Username:         "user",
		Hostname:         "host.com",
		SSHClientVersion: "8.1",
		HardKey:          true,
		Touch2SSH:        false,
		Github:           false,
		// TODO: test marshal and unmarshal of TouchlessSudo.
		TouchlessSudo: nil,
	}
	s, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true github=false"
	if s != want {
		t.Fatalf("expect: %q, got: %q", want, s)
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
	originalCommand := `  key1=value1 key2=value2 key3="a=b" key4`
	expect := map[string]string{
		"key1": "value1", "key2": "value2", "key3": `"a=b"`, "key4": "",
	}
	args := parseAttrs(originalCommand)
	if !reflect.DeepEqual(args, expect) {
		t.Errorf("expect %v, got %v", expect, args)
	}
}
