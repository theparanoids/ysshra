// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//go:build !windows
// +build !windows

package utils

import "net"

// GetConn returns a connection to the agent by dialing to a unix socket.
func GetConn(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
