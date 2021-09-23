package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"go.vzbuilders.com/peng/sshra-oss/agent/ssh/connection"
	"golang.org/x/crypto/ssh"
	ag "golang.org/x/crypto/ssh/agent"
)

// Agent gets the running ssh-agent and its connection
func Agent() (ag.Agent, net.Conn, error) {
	conn, err := AgentConn()
	if err != nil {
		return nil, nil, err
	}

	agent := ag.NewClient(conn)
	return agent, conn, nil
}

// AgentConn returns the connection for ssh agent.
func AgentConn() (net.Conn, error) {
	sshAuthSock, err := CheckSSHAuthSock()
	if err != nil {
		return nil, err
	}
	conn, err := connection.GetConn(sshAuthSock)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// AgentBySocket returns the ssh-agent and its connection by the socket.
func AgentBySocket(socketPath string) (ag.Agent, net.Conn, error) {
	conn, err := connection.GetConn(socketPath)
	if err != nil {
		return nil, nil, err
	}

	agent := ag.NewClient(conn)
	return agent, conn, nil
}

// CheckSSHAuthSock checks for presence of ssh agent and if one present,
// returns the value of SSH_AUTH_SOCK environment variable
func CheckSSHAuthSock() (string, error) {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if strings.TrimSpace(sshAuthSock) == "" {
		return "", errors.New("SSH_AUTH_SOCK is empty")
	}

	// TODO: we can enhance the detection of gpg-agent by talking to it directly.
	// and we need to understand the protocol as stated here
	// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD
	// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent?rev=HEAD
	// http://www.openssh.com/txt/rfc4716.txt (Section 3.5)
	if strings.Contains(sshAuthSock, "gpg-agent") { // match the gpg-agent, instead of ssh-agent
		return "", errors.New("gpg-agent not support")
	}
	return sshAuthSock, nil
}

// ChallengeSSHAgent verifies the given public key using challenge-response authentication.
func ChallengeSSHAgent(a ag.Agent, key ssh.PublicKey) error {
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		return fmt.Errorf("cannot generate random challenge: %v", err)
	}
	sig, err := a.Sign(key, data)
	if err != nil {
		return fmt.Errorf("cannot sign the challenge: %v", err)
	}
	return key.Verify(data, sig)
}
