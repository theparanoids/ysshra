package mock

import (
	"github.com/theparanoids/crypki/proto"
	"testing"
)

func Test_strMatcher_Matches(t *testing.T) {
	tests := []struct {
		name string
		x    *proto.SSHCertificateSigningRequest
		y    *proto.SSHCertificateSigningRequest
		want bool
	}{
		{
			name: "match",
			x: &proto.SSHCertificateSigningRequest{
				Principals: []string{"user1", "user2", "user3"},
				PublicKey:  "public-key",
				Validity:   12345,
				KeyId:      "keyID",
			},
			y: &proto.SSHCertificateSigningRequest{
				Principals: []string{"user1", "user2", "user3"},
				PublicKey:  "public-key",
				Validity:   12345,
				KeyId:      "keyID",
			},
			want: true,
		},
		{
			name: "not match",
			x: &proto.SSHCertificateSigningRequest{
				Principals: []string{"user1", "user2"},
				PublicKey:  "public-key",
				Validity:   12345,
				KeyId:      "keyID",
			},
			y: &proto.SSHCertificateSigningRequest{
				Principals: []string{"user1", "user2", "user3"},
				PublicKey:  "public-key",
				Validity:   12345,
				KeyId:      "keyID",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := String(tt.x)
			if got := matcher.Matches(tt.y); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
