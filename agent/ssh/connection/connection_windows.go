// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package connection

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// GetConn returns a connection to the agent by connecting to a named pipe.
func GetConn(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}
