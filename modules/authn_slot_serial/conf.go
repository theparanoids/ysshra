package authn_slot_serial

type conf struct {
	Slot            string `mapstructure:"slot"`
	YubikeyMappings string `mapstructure:"yubikey_mappings"`
}
