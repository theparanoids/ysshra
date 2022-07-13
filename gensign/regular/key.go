// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package regular

import (
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshura/agent/ssh"
)

// csrAgentKey implements csr.AgentKey.
type csrAgentKey struct {
	*ssh.AgentKey
	csrs []*proto.SSHCertificateSigningRequest
}

func (c *csrAgentKey) addCSR(csr *proto.SSHCertificateSigningRequest) {
	c.csrs = append(c.csrs, csr)
}

// CSRs returns the CSR list of the request.
func (c *csrAgentKey) CSRs() []*proto.SSHCertificateSigningRequest {
	return c.csrs
}
