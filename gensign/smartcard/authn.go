package smartcard

import (
	"github.com/theparanoids/ysshra/csr"
	ag "golang.org/x/crypto/ssh/agent"
)

type authenticator interface {
	authenticate(ag.Agent, *csr.ReqParam) error
}
