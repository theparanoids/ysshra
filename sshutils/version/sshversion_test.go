package version

import (
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
	t.Parallel()
	v := New(8, 0)
	got, want := v.Marshal(), "8.0"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestUnmarshalVersion(t *testing.T) {
	t.Parallel()

	table := []struct {
		label       string
		input       string
		expectError bool
		wantVersion Version
	}{
		{"invalid contains patch", "8.0.0", true, NewDefaultVersion()},
		{"invalid prefix", "OpenSSH_8.0", true, NewDefaultVersion()},
		{"invalid suffix", "8.0p1, LibreSSL 2.6.4", true, NewDefaultVersion()},
		{"valid", "8.0", false, New(8, 0)},
	}

	for _, tt := range table {
		gotVersion, err := Unmarshal(tt.input)
		gotError := err != nil
		if tt.expectError != gotError {
			t.Fatalf("label: %s, got: err=%v want: err=%v", tt.label, gotError, tt.expectError)
		}
		if !reflect.DeepEqual(tt.wantVersion, gotVersion) {
			t.Fatalf("label: %s, got: %v want: %v", tt.label, gotVersion, tt.wantVersion)
		}
	}
}

func TestLessThan(t *testing.T) {
	t.Parallel()

	this := New(8, 1)
	table := []struct {
		label string
		other Version
		want  bool
	}{
		{"less than major", New(9, 0), true},
		{"less than minor", New(8, 2), true},
		{"equal", New(8, 1), false},
		{"larger than major", New(7, 9), false},
		{"larger than minor", New(8, 0), false},
	}

	for _, tt := range table {
		got := this.LessThan(tt.other)
		if tt.want != got {
			t.Fatalf("label: %s, got: %v want: %v", tt.label, got, tt.want)
		}
	}
}
