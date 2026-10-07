// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const certFileSuffix = "-cert.pub"

// StoredCert is a certificate backed up in a CertStore.
type StoredCert struct {
	Cert    *ssh.Certificate
	Comment string
	Path    string
}

// CertStore backs up SSH certificates as one authorized_keys-format file per
// certificate. It only ever holds public material: certificates are public,
// and their private keys stay in hardware. The store is the source of truth
// used to restore a respawned agent.
type CertStore struct {
	Dir string
}

// Put writes cert to the store, replacing an existing copy of the same cert.
func (s *CertStore) Put(cert *ssh.Certificate, comment string) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	if comment != "" {
		line += " " + comment
	}
	path := filepath.Join(s.Dir, certFileName(cert))

	// Write to a temp file and rename, so a crash never leaves a torn cert
	// that a later restore would choke on.
	tmp, err := os.CreateTemp(s.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(line + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Remove deletes cert from the store. Removing a missing cert is not an error.
func (s *CertStore) Remove(cert *ssh.Certificate) error {
	err := os.Remove(filepath.Join(s.Dir, certFileName(cert)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Load returns every certificate in the store. Files that cannot be parsed
// are skipped and reported in the returned error, so one bad file does not
// block restoring the others.
func (s *CertStore) Load() ([]StoredCert, error) {
	paths, err := filepath.Glob(filepath.Join(s.Dir, "*"+certFileSuffix))
	if err != nil {
		return nil, err
	}
	var (
		certs []StoredCert
		errs  []error
	)
	for _, path := range paths {
		sc, err := readCertFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		certs = append(certs, sc)
	}
	return certs, errors.Join(errs...)
}

// Valid returns the stored certificates that have not expired at now.
func (s *CertStore) Valid(now time.Time) ([]StoredCert, error) {
	certs, err := s.Load()
	valid := certs[:0]
	for _, sc := range certs {
		if !Expired(sc.Cert, now) {
			valid = append(valid, sc)
		}
	}
	return valid, err
}

// Prune deletes the certificates that have expired at now and returns them.
func (s *CertStore) Prune(now time.Time) ([]StoredCert, error) {
	certs, err := s.Load()
	var pruned []StoredCert
	for _, sc := range certs {
		if !Expired(sc.Cert, now) {
			continue
		}
		if rmErr := os.Remove(sc.Path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			err = errors.Join(err, rmErr)
			continue
		}
		pruned = append(pruned, sc)
	}
	return pruned, err
}

// NextExpiry returns the earliest ValidBefore among the unexpired stored
// certificates, or false if none of them expires.
func (s *CertStore) NextExpiry(now time.Time) (time.Time, bool) {
	certs, _ := s.Valid(now)
	var next time.Time
	for _, sc := range certs {
		if sc.Cert.ValidBefore == ssh.CertTimeInfinity || sc.Cert.ValidBefore > math.MaxInt64 {
			continue
		}
		t := time.Unix(int64(sc.Cert.ValidBefore), 0)
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	return next, !next.IsZero()
}

// Expired reports whether cert is past its ValidBefore at now. Unlike a full
// validity check it ignores ValidAfter: a cert that is not yet valid because
// of clock skew must not be discarded.
func Expired(cert *ssh.Certificate, now time.Time) bool {
	if cert.ValidBefore == ssh.CertTimeInfinity || cert.ValidBefore > math.MaxInt64 {
		return false
	}
	return now.Unix() > int64(cert.ValidBefore)
}

func certFileName(cert *ssh.Certificate) string {
	sum := sha256.Sum256(cert.Marshal())
	return hex.EncodeToString(sum[:16]) + certFileSuffix
}

func readCertFile(path string) (StoredCert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return StoredCert{}, err
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return StoredCert{}, fmt.Errorf("%s: %w", path, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return StoredCert{}, fmt.Errorf("%s: not an SSH certificate", path)
	}
	return StoredCert{Cert: cert, Comment: comment, Path: path}, nil
}
