package gensign

import (
	"github.com/theparanoids/crypki/proto"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/internal/cert/broker"
	"golang.org/x/crypto/ssh"
)

// BaseHandler is the base of handlers.
type BaseHandler struct {
	broker.Broker
	isPurgeNeeded  bool
	isForHumanUser bool
	handlerName    string
	transID        string
	kid            int
}

// NewBaseHandler creates a base handler.
func NewBaseHandler(broker broker.Broker, handlerName string, isForHumanUser bool) *BaseHandler {
	return &BaseHandler{
		Broker:         broker,
		isPurgeNeeded:  false,
		handlerName:    handlerName,
		isForHumanUser: isForHumanUser,
	}
}

// InitRequest initializes the fields of base Handler by the given param.
func (m *BaseHandler) InitRequest(param csr.ReqParam) (*proto.SSHCertificateSigningRequest, error) {
	// TODO:
	// 1. Get hostname
	// 2. Check options
	// 3. Construct Kid
	// 4. Set transID
	return nil, nil
}

// UpdateCerts updates the certificates.
func (m *BaseHandler) UpdateCerts(certs []ssh.PublicKey, comments []string) error {
	// TODO: implement.
	return nil
}

// PrintMessage prints the message for human users.
func (m *BaseHandler) PrintMessage() {
	// TODO: print message to the announce file.
}
