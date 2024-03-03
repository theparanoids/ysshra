package modules

import (
	"crypto/x509"

	"github.com/theparanoids/ysshra/csr"
)

type CSRModule interface {
	Generate(*csr.ReqParam) ([]csr.AgentKey, error)
}

type CSROption struct {
	// KeyIdentifiers is the mapping from CA public key algorithm to the key identifier configured in signer.
	KeyIdentifiers map[x509.PublicKeyAlgorithm]string
	// KeyIDVersion specifies the version of KeyID.
	KeyIDVersion uint16 `json:"keyid_version"`
}
