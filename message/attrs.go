package message

import "time"

const interfaceVersion = "IFVer=6"

// Attributes stores information that client passes to RA, containing attributes of SSH certificate that the client request for.
type Attributes struct {
	// Username is the user name of client. Required.
	Username string
	// Hostname is the host name of client. Required.
	Hostname      string
	HardKey       bool
	Touch2SSH     bool
	Github        bool
	TouchlessSudo *TouchlessSudo
}

// TouchlessSudo stores information that client passes to RA about touchless sudo.
type TouchlessSudo struct {
	IsFirefighter      bool
	TouchlessSudoHosts string
	TouchlessSudoTime  time.Duration
	// TODO: Figure out why SSHClientVersion is needed only in TouchlessSudo scenario.
	SSHClientVersion string
}
