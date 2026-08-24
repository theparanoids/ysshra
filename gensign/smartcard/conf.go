package smartcard

import "crypto/x509"

type conf struct {
	AuthnModules   []map[string]interface{}           `mapstructure:"authn"`
	CSRModules     []map[string]interface{}           `mapstructure:"csr"`
	KeyIdentifiers map[x509.PublicKeyAlgorithm]string `mapstructure:"key_identifiers"`
}
