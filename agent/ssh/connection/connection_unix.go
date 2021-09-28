//go:build !windows
// +build !windows

package connection

import "net"

// GetConn returns a connection to the agent by dialing to a unix socket.
func GetConn(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
