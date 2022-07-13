// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr

// Generator contains the methods to generate agent keys containing CSRs.
type Generator interface {
	// Generate generates certificate signing requests given by the request param,
	// and returns agent keys containing those CSRs.
	Generate(*ReqParam) ([]AgentKey, error)
}
