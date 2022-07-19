// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package gensign

import (
	"net"

	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
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
