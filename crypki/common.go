package crypki

// SSHUserKeyID - key identifier for user ssh certificate signing key.
const SSHUserKeyID = "ssh-user-key"

// GetDefaultExtension returns default extensions for user SSH certificate.
func GetDefaultExtension() map[string]string {
	exts := make(map[string]string)
	exts["permit-pty"] = ""
	exts["permit-X11-forwarding"] = ""
	exts["permit-agent-forwarding"] = ""
	exts["permit-port-forwarding"] = ""
	exts["permit-user-rc"] = ""
	return exts
}
