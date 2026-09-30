// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package modules

import (
	"crypto/x509"

	"github.com/theparanoids/ysshra/csr"
)

// CSRModule is the interface to generate CSR for a handler.
type CSRModule interface {
	Generate(*csr.ReqParam) ([]csr.AgentKey, error)
}

// CSROption is the option struct to create a CSR module.
type CSROption struct {
	// KeyIdentifiers is the mapping from CA public key algorithm to the key identifier configured in signer.
	KeyIdentifiers map[x509.PublicKeyAlgorithm]string
	// KeyIDVersion specifies the version of KeyID.
	KeyIDVersion uint16 `json:"keyid_version"`
}
