// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import (
	"math"
	"time"

	"golang.org/x/crypto/ssh"
)

// ValidateSSHCertTime returns true if the certificate is not expired at current time.
func ValidateSSHCertTime(cert *ssh.Certificate, currentTime time.Time) bool {
	if cert == nil {
		return false
	}
	now := currentTime
	if now.IsZero() {
		now = time.Now()
	}
	vb := cert.ValidBefore
	va := cert.ValidAfter
	if vb > math.MaxInt64 {
		vb = math.MaxInt64
	}
	if va > math.MaxInt64 {
		va = math.MaxInt64
	}
	if int64(va) > now.Unix() || now.Unix() > int64(vb) {
		return false
	}
	return true
}
