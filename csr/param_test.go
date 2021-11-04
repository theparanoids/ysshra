package csr

import (
	"reflect"
	"testing"

	"go.vzbuilders.com/peng/sshra-oss/common"
	"go.vzbuilders.com/peng/sshra-oss/message"
)

func TestNewReqParam(t *testing.T) {
	t.Parallel()
	goodEnvGetter := func(s string) string {
		m := map[string]string{
			"SSH_CONNECTION":       "1.2.3.4 36673 192.168.223.229 22",
			"LOGNAME":              "user",
			"SSH_ORIGINAL_COMMAND": "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true github=false",
		}
		return m[s]
	}
	goodOSArgsGetter := func() []string {
		return []string{"/usr/bin/gen-sign", "NONS", "Regular"}
	}
	tests := map[string]struct {
		envGetter        func(string) string
		osArgsGetter     func() []string
		hostNameGetter   func() (string, error)
		wantErr          bool
		expectedReqParam *ReqParam
	}{
		"happy path": {
			envGetter:    goodEnvGetter,
			osArgsGetter: goodOSArgsGetter,
			expectedReqParam: &ReqParam{
				NamespacePolicy:  common.NoNamespace,
				HandlerName:      "Regular",
				ClientIP:         "1.2.3.4",
				LogName:          "user",
				ReqUser:          "user",
				ReqHost:          "host.com",
				SSHClientVersion: "8.1",
				Attrs: &message.Attributes{
					Username:         "user",
					Hostname:         "host.com",
					SSHClientVersion: "8.1",
					HardKey:          true,
					Touch2SSH:        false,
					Github:           false,
					TouchlessSudo:    nil,
				},
			},
		},
		"invalid SSH_CONNECTION": {
			envGetter: func(s string) string {
				m := map[string]string{
					"LOGNAME":              "user",
					"SSH_ORIGINAL_COMMAND": "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true github=false",
				}
				return m[s]
			},
			osArgsGetter: goodOSArgsGetter,
			wantErr:      true,
		},
		"invalid LOGNAME": {
			envGetter: func(s string) string {
				m := map[string]string{
					"SSH_CONNECTION":       "1.2.3.4 36673 192.168.223.229 22",
					"SSH_ORIGINAL_COMMAND": "IFVer=6 SSHClientVersion=8.1 req=user@host.com HardKey=true github=false",
				}
				return m[s]
			},
			osArgsGetter: goodOSArgsGetter,
			wantErr:      true,
		},
		"invalid SSH_ORIGINAL_COMMAND": {
			envGetter: func(s string) string {
				m := map[string]string{
					"SSH_CONNECTION": "1.2.3.4 36673 192.168.223.229 22",
					"LOGNAME":        "user",
				}
				return m[s]
			},
			osArgsGetter: goodOSArgsGetter,
			wantErr:      true,
		},
		"invalid os args": {
			envGetter: goodEnvGetter,
			osArgsGetter: func() []string {
				return []string{"/usr/bin/gen-sign", "Regular"}
			},
			wantErr: true,
		},
		"invalid namespace policy": {
			envGetter: goodEnvGetter,
			osArgsGetter: func() []string {
				return []string{"/usr/bin/gen-sign", "trash", "Regular"}
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			param, err := NewReqParam(test.envGetter, test.osArgsGetter)
			if err == nil && test.wantErr {
				t.Fatalf("%s: want error but got no error", name)
			}
			if err != nil && !test.wantErr {
				t.Fatalf("%s: want no error but got error: %v", name, err)
			}
			if test.wantErr {
				return
			}
			param.TransID = ""
			if !reflect.DeepEqual(param, test.expectedReqParam) {
				t.Fatalf("%s: want: %+v, got: %+v", name, test.expectedReqParam, param)
			}
		})
	}
}
