package ssh

import (
	"go.vzbuilders.com/peng/sshra-oss/sshutils/key"
	"golang.org/x/crypto/ssh/agent"
)

const (
	defaultKeyValiditySec  = 12 * 3600 // 12 hours
	defaultPublicKeyAlgo   = key.RSA2048
	defaultPrivateKeyLabel = "private-key"
	defaultCertLabel       = "certificate"
)

// keyFilter is the function to determine whether a key is the target key or cert for that handler.
// It's useful to access/remove the keys from the SSH agent.
type keyFilter func(key *agent.Key) bool

// DefaultKeyOpt is the default option of keyAgent.
var DefaultKeyOpt = KeyOpt{
	KeyRefreshFilter: func(key *agent.Key) bool {
		// Default key filter does not filter any keys.
		return false
	},
	PrivateKeyValiditySec: defaultKeyValiditySec,
	PublicKeyAlgo:         defaultPublicKeyAlgo,
	PrivateKeyLabel:       defaultPrivateKeyLabel,
	CertLabel:             defaultCertLabel,
}

// KeyOpt is the option for AgentKey.
type KeyOpt struct {
	// keyFilter is the function to determine whether a key is the target key or cert for that handler.
	KeyRefreshFilter      keyFilter
	PrivateKeyValiditySec uint32
	PrivateKeyLabel       string
	CertLabel             string
	PublicKeyAlgo         key.PublicKeyAlgo
}
