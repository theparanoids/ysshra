package smartcard

import (
	"net"

	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/gensign"
)

const (
	// HandlerName is a unique name to identify a handler.
	HandlerName = "paranoids.smartcard"
)

// Handler implements gensign.Handler.
type Handler struct {
}

// NewHandler creates an SSH agent the ssh connection,
// and constructs a gensign.Handler containing the options loaded from conf.
func NewHandler(gensignConf *config.GensignConfig, conn net.Conn) (gensign.Handler, error) {
	// TODO
	return nil, nil
}

// Name returns the name of the handler.
func (h *Handler) Name() string {
	return HandlerName
}

// Authenticate succeeds if the user is allowed to use request the certificate based on the public key on server side's directory.
func (h *Handler) Authenticate(param *csr.ReqParam) error {
	// TODO
	return nil
}

func (h *Handler) Generate(param *csr.ReqParam) ([]csr.AgentKey, error) {
	// TODO
	return nil, nil
}
