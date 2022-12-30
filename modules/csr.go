package modules

import (
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/csr"
	"golang.org/x/crypto/ssh/agent"
)

type CSRModule interface {
	Generate(agent.Agent, *csr.ReqParam) ([]*proto.SSHCertificateSigningRequest, error)
}
