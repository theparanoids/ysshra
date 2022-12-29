package smartcard

import "crypto/x509"

const (
	pivRootCADefaultPath = "/opt/sshca/RA/piv_root_ca.pem"
	u2fRootCADefaultPath = "/opt/sshca/RA/u2f_root_ca.pem"
	// f9CertsDirDefault holds the attestation certs provided by Yubico.
	f9CertsDirDefault = "/opt/sshca/RA/f9_certs/"
	// nonceDirPath specifies the directory path which stores nonce transaction files.
	nonceDirPathDefault = "/var/sshra/nonce"
)

type conf struct {
	YubiKeyMappings string                             `mapstructure:"yubikey_mappings"`
	FireFighterList string                             `mapstructure:"firefighter_list"`
	UserSlot        string                             `mapstructure:"user_slot"`
	EmergencySlot   string                             `mapstructure:"emergency_slot"`
	PIVRootCA       string                             `mapstructure:"piv_root_ca"`
	U2FRootCA       string                             `mapstructure:"u2f_root_ca"`
	F9CertsDir      string                             `mapstructure:"f9_certs_dir"`
	EnableTouch2SSH bool                               `mapstructure:"enable_touch2ssh,omitempty"`
	NonceDirPath    string                             `mapstructure:"nonce_dir_path"`
	KeyIdentifiers  map[x509.PublicKeyAlgorithm]string `mapstructure:"key_identifiers"`
}

func newDefaultConf() *conf {
	return &conf{
		PIVRootCA:    pivRootCADefaultPath,
		U2FRootCA:    u2fRootCADefaultPath,
		F9CertsDir:   f9CertsDirDefault,
		NonceDirPath: nonceDirPathDefault,
	}
}
