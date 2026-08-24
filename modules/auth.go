package modules

import (
	"github.com/theparanoids/ysshra/csr"
)

type AuthnModule interface {
	Authenticate(*csr.ReqParam) error
}
