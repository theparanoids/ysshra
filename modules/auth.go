// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package modules

import (
	"github.com/theparanoids/ysshra/csr"
)

// AuthnModule is the interface to authenticate an SSH certificate request for a handler.
type AuthnModule interface {
	Authenticate(*csr.ReqParam) error
}
