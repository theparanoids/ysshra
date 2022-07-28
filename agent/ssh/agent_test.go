// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"

	ag "golang.org/x/crypto/ssh/agent"
)

func TestCheckSSHAuthSock(t *testing.T) {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	defer os.Setenv("SSH_AUTH_SOCK", sshAuthSock)

	os.Setenv("SSH_AUTH_SOCK", "")
	want := "SSH_AUTH_SOCK is empty"
	_, err := CheckSSHAuthSock()
	if err == nil || err.Error() != want {
		t.Errorf(`expect "%s", got "%v"`, want, err)
	}

	os.Setenv("SSH_AUTH_SOCK", "/var/tmp/gnupg/S.gpg-agent")
	want = "gpg-agent not support"
	_, err = CheckSSHAuthSock()
	if err == nil || err.Error() != want {
		t.Errorf(`expect "%s", got "%v"`, want, err)
	}

	os.Setenv("SSH_AUTH_SOCK", "/root/.yubiagent/sock")
	want = "/root/.yubiagent/sock"
	socket, err := CheckSSHAuthSock()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if socket != want {
		t.Errorf(`expect "%s", got "%v"`, want, socket)
	}
}

func TestChallengeSSHAgent(t *testing.T) {
	a := ag.NewKeyring()
	for i := 0; i < 10; i++ {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Add(ag.AddedKey{PrivateKey: private}); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		err = ChallengeSSHAgent(a, key)
		if err != nil {
			t.Fatal(err)
		}
	}
}
