package gensign

import (
	"net"

	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/csr"
)

// CreateHandler is the interface function to initialize Handler.
type CreateHandler func(gensignConf *config.GensignConfig, conn net.Conn) (Handler, error)

// Handler describes an external handler that can extend the functionality of
// a standard gensign command.
type Handler interface {
	csr.Generator
	Name() string
	Authenticate(params *csr.ReqParam) error
}
