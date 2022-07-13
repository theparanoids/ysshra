// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr

import (
	"context"

	"github.com/theparanoids/crypki/proto"
	"golang.org/x/crypto/ssh"
)

// Signer describes an external structure that encapsulates the process to sign certificate requests.
type Signer interface {
	// Sign signs the given CSR and returns the signed certificate and the corresponding comment.
	Sign(ctx context.Context, request *proto.SSHCertificateSigningRequest) (cert []ssh.PublicKey, comment []string, err error)
}
