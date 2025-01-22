package authn_slot_attest

type conf struct {
	Slot      string `mapstructure:"slot"`
	PIVRootCA string `mapstructure:"piv_root_ca"`
	U2FRootCA string `mapstructure:"u2f_root_ca"`
}
