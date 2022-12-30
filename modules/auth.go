package modules

import (
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/csr"
	"golang.org/x/crypto/ssh/agent"
)

type AuthModule interface {
	Authenticate(agent.Agent, *csr.ReqParam) error
}

type SlotAuthModule interface {
	Authenticate(*yubiagent.SlotAgent, *csr.ReqParam) error
}
