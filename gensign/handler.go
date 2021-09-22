package gensign

import (
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"golang.org/x/crypto/ssh"
)

// Handler describes an external handler that can extend the functionality of
// a standard gensign command.
type Handler interface {
	csr.Generator
	Authenticate(params *csr.ReqParam) error
	UpdateCerts(certs []ssh.PublicKey, comments []string) error
}
