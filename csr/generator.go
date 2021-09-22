package csr

import "github.com/theparanoids/crypki/proto"

// Generator contains the methods to generate a CSR.
type Generator interface {
	// Generate generates a certificate signing request given the ReqParam.
	Generate(*ReqParam) ([]*proto.SSHCertificateSigningRequest, error)
}
