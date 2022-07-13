// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package shimagent

import (
	"go.uber.org/multierr"
	"time"

	certutil "github.com/theparanoids/ysshura/sshutils/cert"
	keyutil "github.com/theparanoids/ysshura/sshutils/key"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type helperShimAgentServer interface {
	remove(ssh.PublicKey) error
}

type remover func(ssh.PublicKey) error

func (r remover) remove(key ssh.PublicKey) error {
	return r(key)
}

func filterExpiredCerts(s helperShimAgentServer,
	certsInMemory map[hashcode]*certificate,
	keysInAgent []*agent.Key) error {
	now := time.Now()

	var errs error
	remove := func(key ssh.PublicKey) {
		errs = multierr.Append(errs, s.remove(key))
	}
	// In-agent cert needs to verify first to prevent multiple removals.
	for _, key := range keysInAgent {
		cert, err := keyutil.CastSSHPublicKeyToCertificate(key)
		if err != nil {
			continue
		}

		if !certutil.ValidateSSHCertTime(cert, now) {
			remove(cert)
		}
	}
	for _, cert := range certsInMemory {
		if !certutil.ValidateSSHCertTime(cert.Certificate, now) {
			remove(cert.Certificate)
		}
	}
	if errs != nil {
		return errs
	}
	return nil
}

// filterOrphanCerts filters out certificates that have no public keys backed in the agent.
func filterOrphanCerts(s helperShimAgentServer,
	certsInMemory map[hashcode]*certificate,
	keysInAgent []*agent.Key) error {
	// Ignore the cases that an empty key list is returned when listing keys in the agent. Because the
	// agent might be locked and not accessible.
	if len(keysInAgent) == 0 {
		return nil
	}

	// publicKeys holds the public key of SSH certificates.
	publicKeys := make(map[hashcode]struct{})

	for _, key := range keysInAgent {
		cert, err := keyutil.CastSSHPublicKeyToCertificate(key)
		if err == nil {
			publicKeys[hash(cert.Key.Marshal())] = struct{}{}
		} else {
			publicKeys[hash(key.Marshal())] = struct{}{}
		}
	}

	var errs error
	for _, cert := range certsInMemory {
		if _, ok := publicKeys[hash(cert.Key.Marshal())]; !ok {
			errs = multierr.Append(errs, s.remove(cert.Certificate))
		}
	}
	if errs != nil {
		return errs
	}
	return nil
}
