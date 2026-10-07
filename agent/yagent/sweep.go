// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Sweep removes expired certificates from the agent and from the store. The
// agent itself never drops an expired certificate, and ssh would keep offering
// it, wasting one of the server's MaxAuthTries attempts.
//
// OpenSSH applies a lifetime constraint to a whole provider load rather than to
// each certificate, so expiry has to be enforced from the outside like this.
func Sweep(ag agent.Agent, store *CertStore, now time.Time) (removed []*ssh.Certificate, err error) {
	keys, err := ag.List()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, key := range keys {
		pub, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok || !Expired(cert, now) {
			continue
		}
		if err := ag.Remove(cert); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, cert)
	}
	if store != nil {
		if _, err := store.Prune(now); err != nil {
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}
