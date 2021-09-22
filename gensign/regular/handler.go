package regular

import (
	"errors"
	"net"

	"github.com/theparanoids/crypki/proto"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/internal/cert/broker"
)

const (
	// HandlerName is a unique name to identify a handler.
	HandlerName = "SSHRA Regular User Handler"
	// IsForHumanUser indicates whether this handler should be used for a human user.
	IsForHumanUser = true
)

// Handler implements gensign.Handler.
type Handler struct {
	*gensign.BaseHandler
}

// NewHandler creates a certificate broker via the ssh connection,
// and constructs a gensign.Handler containing the options loaded from conf.
func NewHandler(conf *config.GensignConfig, conn net.Conn) gensign.Handler {
	// TODO: process conf.
	agent := broker.NewSSHCertBroker(conn)
	return &Handler{
		BaseHandler: gensign.NewBaseHandler(agent, HandlerName, IsForHumanUser),
	}
}

// Authenticate succeeds if the user is allowed to use OTP to get a certificate.
func (h *Handler) Authenticate(params *csr.ReqParam) error {
	// TODO:
	// Check request param.
	// Check agent public keys.
	return errors.New("not implemented")
}

// Generate implements csr.Generator.
func (h *Handler) Generate(param *csr.ReqParam) ([]*proto.SSHCertificateSigningRequest, error) {
	// TODO
	// 1. Generate new key pair
	// 2. Process keyId
	// 3. Append certificate requests to the return slice
	return nil, nil
}
