package cert

import (
	"reflect"
	"testing"
)

func TestGetPrincipals(t *testing.T) {
	tests := []struct {
		name      string
		prinsConf string
		logName   string
		want      []string
	}{
		{
			name:      "happy path",
			prinsConf: "<logname>,<logname>:123,test:<logname>",
			logName:   "example_user",
			want:      []string{"example_user", "example_user:123", "test:example_user"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPrincipals(tt.prinsConf, tt.logName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPrincipals() = %v, want %v", got, tt.want)
			}
		})
	}
}
