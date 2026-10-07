// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSweep(t *testing.T) {
	now := time.Now()
	ring := agent.NewKeyring()
	store := &CertStore{Dir: t.TempDir()}

	priv, pub := newTestKey(t)
	valid := newTestCert(t, pub, "valid", now.Add(time.Hour))
	expired := newTestCert(t, pub, "expired", now.Add(-time.Minute))
	for _, c := range []*ssh.Certificate{valid, expired} {
		if err := ring.Add(agent.AddedKey{PrivateKey: priv, Certificate: c}); err != nil {
			t.Fatal(err)
		}
		if err := store.Put(c, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := ring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}

	removed, err := Sweep(ring, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].KeyId != "expired" {
		t.Fatalf("removed %d certs, want only %q", len(removed), "expired")
	}

	keys, err := ring.List()
	if err != nil {
		t.Fatal(err)
	}
	var certIDs []string
	plainKeys := 0
	for _, k := range keys {
		p, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			t.Fatal(err)
		}
		if c, ok := p.(*ssh.Certificate); ok {
			certIDs = append(certIDs, c.KeyId)
		} else {
			plainKeys++
		}
	}
	if len(certIDs) != 1 || certIDs[0] != "valid" || plainKeys != 1 {
		t.Fatalf("agent holds certs %v and %d plain keys; want [valid] and 1", certIDs, plainKeys)
	}

	stored, _ := store.Load()
	if len(stored) != 1 || stored[0].Cert.KeyId != "valid" {
		t.Fatalf("store holds %d certs, want only %q", len(stored), "valid")
	}
}
