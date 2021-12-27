package regular

import "crypto/x509"

type conf struct {
	// PubKeyDir specifies the folder path which stores users' public keys.
	PubKeyDir string `mapstructure:"pub_key_dir"`
	// KeyIdentifiers is the mapping from CA public key algorithm to the key identifier configured in signer.
	KeyIdentifiers map[x509.PublicKeyAlgorithm]string `mapstructure:"key_identifiers"`
}
