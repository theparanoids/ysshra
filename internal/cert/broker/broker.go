package broker

import "golang.org/x/crypto/ssh"

// Broker describes the process of adding/purging keys to/from an agent.
type Broker interface {
	AddPubKeys(keys []ssh.PublicKey, comments []string) error
	AddPrivateKeys(keys []interface{}, comments []string) error
	PurgeCerts() error
}
