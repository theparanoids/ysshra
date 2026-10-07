// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCertStorePutLoad(t *testing.T) {
	store := &CertStore{Dir: filepath.Join(t.TempDir(), "certs")}
	_, pub := newTestKey(t)
	cert := newTestCert(t, pub, "touchless", time.Now().Add(time.Hour))

	if err := store.Put(cert, "slot-9a"); err != nil {
		t.Fatal(err)
	}
	// Putting the same cert again replaces it instead of duplicating it.
	if err := store.Put(cert, "slot-9a"); err != nil {
		t.Fatal(err)
	}
	certs, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if !bytes.Equal(certs[0].Cert.Marshal(), cert.Marshal()) || certs[0].Comment != "slot-9a" {
		t.Fatalf("loaded %q/%q, want the stored cert", certs[0].Cert.KeyId, certs[0].Comment)
	}

	info, err := os.Stat(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("store dir mode = %o, want 700", perm)
	}
}

func TestCertStoreSkipsBadFiles(t *testing.T) {
	store := &CertStore{Dir: t.TempDir()}
	_, pub := newTestKey(t)
	if err := store.Put(newTestCert(t, pub, "good", time.Now().Add(time.Hour)), ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "junk"+certFileSuffix), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A plain public key is not a certificate and must not be loaded.
	if err := os.WriteFile(filepath.Join(store.Dir, "plain"+certFileSuffix), ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := store.Load()
	if err == nil {
		t.Fatal("expected an error for the unparsable files")
	}
	if len(certs) != 1 || certs[0].Cert.KeyId != "good" {
		t.Fatalf("got %d certs, want only the good one", len(certs))
	}
}

func TestCertStoreValidPruneNextExpiry(t *testing.T) {
	store := &CertStore{Dir: t.TempDir()}
	now := time.Now()
	_, pub := newTestKey(t)
	soon := newTestCert(t, pub, "soon", now.Add(time.Minute))
	later := newTestCert(t, pub, "later", now.Add(time.Hour))
	gone := newTestCert(t, pub, "gone", now.Add(-time.Minute))
	for _, c := range []*ssh.Certificate{soon, later, gone} {
		if err := store.Put(c, ""); err != nil {
			t.Fatal(err)
		}
	}

	valid, err := store.Valid(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) != 2 {
		t.Fatalf("got %d valid certs, want 2", len(valid))
	}

	next, ok := store.NextExpiry(now)
	if !ok || next.Unix() != int64(soon.ValidBefore) {
		t.Fatalf("NextExpiry = %v, %v; want %v", next, ok, time.Unix(int64(soon.ValidBefore), 0))
	}

	pruned, err := store.Prune(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0].Cert.KeyId != "gone" {
		t.Fatalf("pruned %d certs, want only %q", len(pruned), "gone")
	}
	if all, _ := store.Load(); len(all) != 2 {
		t.Fatalf("store has %d certs after prune, want 2", len(all))
	}
}

func TestExpired(t *testing.T) {
	now := time.Now()
	_, pub := newTestKey(t)
	notYetValid := newTestCert(t, pub, "future", now.Add(2*time.Hour))
	notYetValid.ValidAfter = uint64(now.Add(time.Hour).Unix())

	tests := []struct {
		name string
		cert *ssh.Certificate
		want bool
	}{
		{"valid", newTestCert(t, pub, "v", now.Add(time.Hour)), false},
		{"expired", newTestCert(t, pub, "e", now.Add(-time.Second)), true},
		{"forever", &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}, false},
		// Clock skew must not make yagent discard a freshly issued cert.
		{"not yet valid", notYetValid, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Expired(tt.cert, now); got != tt.want {
				t.Fatalf("Expired = %v, want %v", got, tt.want)
			}
		})
	}
}
