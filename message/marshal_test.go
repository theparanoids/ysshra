package message

import (
	"reflect"
	"testing"
)

// TODO: add more tests.
func TestMarshal(t *testing.T) {
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
	s, err := Marshal(a)
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
