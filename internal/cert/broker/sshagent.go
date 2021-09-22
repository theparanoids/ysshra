package broker

import (
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHAgentBroker manipulates ssh keys via ssh-agent.
type SSHAgentBroker struct {
	agent agent.Agent
}

// NewSSHCertBroker initializes an SSHAgentBroker from the network connection.
func NewSSHCertBroker(conn net.Conn) *SSHAgentBroker {
	return &SSHAgentBroker{}
}

// AddPubKeys adds the certificate or the public key to the agent.
func (b *SSHAgentBroker) AddPubKeys(keys []ssh.PublicKey, comments []string) error {
	// TODO: implement.
	return nil
}

// AddPrivateKeys adds the private key to the agent.
func (b *SSHAgentBroker) AddPrivateKeys(keys []interface{}, comments []string) error {
	// TODO: implement.
	return nil
}

func (b *SSHAgentBroker) PurgeCerts() error {
	// TODO: implement.
	return nil
}
