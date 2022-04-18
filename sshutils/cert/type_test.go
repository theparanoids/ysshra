// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSCCertLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		keyID           string
		criticalOptions map[string]string
		certNil         bool
		expectError     bool
		expectLabel     string
	}{
		{
			name:        "touch-cert",
			keyID:       `{"prins":["user"],"transID":"22dde224","reqUser":"user","reqIP":"1.1.1.1","reqHost":"host","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`,
			certNil:     false,
			expectError: false,
			expectLabel: "TouchSudoSSH-22dde224",
		},
		{
			name:        "touchless-cert",
			keyID:       `{"prins":["user"],"transID":"22dde224","reqUser":"user","reqIP":"1.1.1.1","reqHost":"C02XF22WJHD3","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
			certNil:     false,
			expectError: false,
			expectLabel: "TouchlessSSH-22dde224",
		},
		{
			name:            "touchless-sudo-cert",
			keyID:           `{"prins":["user"],"transID":"22dde224","reqUser":"user","reqIP":"1.1.1.1","reqHost":"C02XF22WJHD3","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`,
			criticalOptions: map[string]string{"touchless-sudo-hosts": "www.example.com"},
			certNil:         false,
			expectError:     false,
			expectLabel:     "TouchlessSudoSSH-22dde224",
		},
		{
			name:            "touchless-sudo-in-agent-cert",
			keyID:           `{"prins":["pchen06"],"transID":"01136295cb","reqUser":"pchen06","reqIP":"203.83.216.28","reqHost":"C02XM196JGH6","isFirefighter":true,"isHWKey":false,"isHeadless":false,"isNonce":false,"usage":0,"touchPolicy":0,"ver":1}`,
			criticalOptions: map[string]string{"touchless-sudo-hosts": "www.example.com"},
			certNil:         false,
			expectError:     false,
			expectLabel:     "TouchlessSudoInAgentSSH-01136295cb",
		},
		{
			name:        "firefighter-cert",
			keyID:       `{"prins":["user"],"transID":"22dde224","reqUser":"user","reqIP":"1.1.1.1","reqHost":"C02XF22WJHD3","isFirefighter":true,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`,
			certNil:     false,
			expectError: false,
			expectLabel: "FireFighterSudoSSH-22dde224",
		},
		{
			name:            "nonce-cert",
			keyID:           `{"prins":["user"],"transID":"22dde224","reqUser":"user","reqIP":"1.1.1.1","reqHost":"C02XF22WJHD3","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":true,"touchPolicy":1,"ver":1}"`,
			criticalOptions: map[string]string{"noncetool": "user@example.com"},
			certNil:         false,
			expectError:     false,
			expectLabel:     "NonceSSH-22dde224",
		},
		{
			name:        "bad-keyid",
			keyID:       "bad keyID",
			certNil:     false,
			expectError: true,
			expectLabel: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert, _ := testSSHCertificate(t, tt.keyID, &ssh.Permissions{CriticalOptions: tt.criticalOptions})
			if tt.certNil {
				cert = nil
			}
			label, err := Label(cert)
			if err != nil {
				if !tt.expectError {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if label != tt.expectLabel {
				t.Errorf("label mismatch: got: %v, want: %v", label, tt.expectLabel)
			}
		})
	}
}
