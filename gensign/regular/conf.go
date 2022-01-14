package regular

import "crypto/x509"

const (
	defaultCertLabel       = "regular"
	defaultPubKeyDir       = "/etc/ssh/authorized_public_keys"
	defaultCertValiditySec = 12 * 3600 // 12 hours
)

type conf struct {
	// PubKeyDir specifies the folder path which stores users' public keys.
	PubKeyDir string `mapstructure:"pub_key_dir"`
	// KeyIdentifiers is the mapping from CA public key algorithm to the key identifier configured in signer.
	KeyIdentifiers map[x509.PublicKeyAlgorithm]string `mapstructure:"key_identifiers"`
	// CertLabel is the comment followed by the provisioned cert.
	CertLabel string `mapstructure:"key_label"`
	// CertValiditySec is the time length of cert validity.
	CertValiditySec uint64 `mapstructure:"cert_validity_sec"`
}

func NewDefaultConf() *conf {
	return &conf{
		PubKeyDir:       defaultPubKeyDir,
		CertLabel:       defaultCertLabel,
		CertValiditySec: defaultCertValiditySec,
	}
}
