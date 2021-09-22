package agent

import (
	"net"
)

// SSHAgentConn returns the connection for ssh agent.
func SSHAgentConn() (net.Conn, error) {
	// TODO: check SSHAuthSock path.
	// TODO: create the connection to ssh-agent
	return nil, nil
}
