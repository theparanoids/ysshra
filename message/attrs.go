package message

const legacyInterfaceVersion = "IFVer=6"

// Attributes stores information that client passes to RA, containing attributes of SSH certificate that the client request for.
type Attributes struct {
	// IfVer is the version of the gensign attributes interface version.
	IfVer int `json:"ifVer"`
	// Username is the user name of client. Required.
	Username string `json:"username"`
	// Hostname is the host name of client. Required.
	Hostname string `json:"hostname"`
	// SSHClientVersion is the ssh version on the requester host. Required.
	SSHClientVersion string `json:"sshClientVersion"`
	// HardKey indicates whether the request is associated to a public key backed in a smartcard hardware.
	HardKey       bool           `json:"hardKey"`
	Touch2SSH     bool           `json:"touch2SSH"`
	Github        bool           `json:"github"`
	Nonce         bool           `json:"nonce"`
	TouchlessSudo *TouchlessSudo `json:"touchlessSudo"`
}

// TouchlessSudo stores information that client passes to RA about touchless sudo.
type TouchlessSudo struct {
	// IsFirefighter indicates whether the requested certificate should be a firefighter cert or not.
	IsFirefighter bool `json:"isFirefighter"`
	// TouchlessSudoHosts are the destination host list that accept the requested touchless certificate.
	TouchlessSudoHosts string `json:"touchlessSudoHosts"`
	// TouchlessSudoTime indicates the valid time period of the touchless certificate (in minutes).
	TouchlessSudoTime int64 `json:"touchlessSudoTime"`
}
