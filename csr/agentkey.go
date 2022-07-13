// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr

import (
	"github.com/theparanoids/crypki/proto"
	"golang.org/x/crypto/ssh"
)

// AgentKey represents a private key in ssh agent, but also holds certificate signing requests.
// It interacts with the client agent to insert certificates.
// A CSR agent key operates certificates for one private key only.
type AgentKey interface {
	CSRs() []*proto.SSHCertificateSigningRequest
	AddCertsToAgent(certs []ssh.PublicKey, comments []string) error
}
