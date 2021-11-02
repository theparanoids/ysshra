package regular

type conf struct {
	// Enable indicates whether the handler is enabled or not.
	Enable bool
	// PubKeyDir specifies the folder path which stores users' public keys.
	PubKeyDir string `mapstructure:"pub_key_dir"`
}
