// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import (
	"reflect"
	"testing"
)

func TestGetPrincipalsLegacy(t *testing.T) {
	tests := []struct {
		name       string
		principals []string
		certType   Type
		want       []string
	}{
		{
			name:       "unkown",
			principals: []string{"user1", "user2"},
			certType:   UnknownCertType,
			want:       nil,
		},
		{
			name:       "TouchSudoCert",
			principals: []string{"user1", "user2"},
			certType:   TouchSudoCert,
			want:       []string{"user1:touch", "user2:touch"},
		},
		{
			name:       "TouchlessSudoCert",
			principals: []string{"user1", "user2"},
			certType:   TouchlessSudoCert,
			want:       []string{"user1:notouch", "user2:notouch"},
		},
		{
			name:       "TouchlessCert",
			principals: []string{"user1", "user2"},
			certType:   TouchlessCert,
			want:       []string{"user1:notouch", "user2:notouch"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPrincipalsLegacy(tt.principals, tt.certType); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPrincipals() = %v, want %v", got, tt.want)
			}
		})
	}
}
