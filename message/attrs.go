package message

import (
	"crypto/x509"
)

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
	// PubKeyAlgo is to specify the CA public key algorithm for the requested certificate.
	// It would be mapped to an identifier string of a key slot in CA.
	PubKeyAlgo x509.PublicKeyAlgorithm `json:"pubKeyAlgo,omitempty"`
	// SignatureAlgo is the signing algorithm of the requested certificate. (Not implemented.)
	SignatureAlgo x509.SignatureAlgorithm `json:"signatureAlgo,omitempty"`
	// HardKey indicates whether the request is associated to a public key backed in a smartcard hardware.
	HardKey bool `json:"hardKey"`
	// Touch2SSH indicates whether the requested certificate requires a touch during SSH login challenge.
	Touch2SSH bool `json:"touch2SSH,omitempty"`
	// TouchlessSudo indicates whether the requested certificate is touchless during SUDO challenge.
	TouchlessSudo *TouchlessSudo `json:"touchlessSudo,omitempty"`
	// Exts contains the extended key value mappings. It is useful to add extra fields for specific handlers or modules.
	Exts map[string]interface{} `json:"exts,omitempty"`
}

// TouchlessSudo stores information that client passes to RA about touchless sudo.
type TouchlessSudo struct {
	// IsFirefighter indicates whether the requested certificate should be a firefighter cert or not.
	IsFirefighter bool `json:"isFirefighter,omitempty"`
	// Hosts are the destination host list that accept the requested touchless certificate.
	Hosts string `json:"hosts,omitempty"`
	// Time indicates the valid time period of the touchless certificate (in minutes).
	Time int64 `json:"time,omitempty"`
}
