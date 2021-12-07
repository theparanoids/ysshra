package regular

type conf struct {
	// PubKeyDir specifies the folder path which stores users' public keys.
	PubKeyDir string `mapstructure:"pub_key_dir"`
}
