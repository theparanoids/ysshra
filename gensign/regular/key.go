package regular

import (
	"github.com/theparanoids/crypki/proto"
	"go.vzbuilders.com/peng/sshra-oss/agent/ssh"
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
