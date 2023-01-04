package authn_f9_verify

type conf struct {
	// F9CertsDir stores all the authorized f9 certificates.
	F9CertsDir string `mapstructure:"f9_certs_dir"`
}
