package keyid

import (
	"encoding/json"
	"fmt"
)

// About KeyID Versioning:
// Things that have to be taken care of when creating a new KeyID version:
// - Don't ever remove the `Version` field
// - Remove the old fields only when all the supported versions don't reference them
// - Specify required keys and sanity checker for the new version,
//   and a no-op sanity checker is provided for convenience
// Things that can be achieved with KeyID versioning:
// - Add new fields
// - Replace the semantics of old fields with new fields,
//   and the code referencing the KeyID struct can decide
//   which fields to look at depending on the version
// - Add version-specific sanity check to certain fields in Marshal() and Unmarshal()

// MsgUnsupportedVersion should be used as the error message when the version of KeyID is not supported.
const MsgUnsupportedVersion = "unsupported Key ID version: %d"

// TouchPolicy is an integer that indicates the touch policy
// of a certificate.
// For the touch operation, currently it is only available in YubiKey 4 or later.
//
// Reference: https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
type TouchPolicy int

const (
	// DefaultTouch indicates that the default touch behaviour for a key slot is used.
	DefaultTouch TouchPolicy = iota
	// NeverTouch indicates that the touch is never required for operations.
	NeverTouch
	// AlwaysTouch indicates that the touch is always required for operations.
	AlwaysTouch
	// CachedTouch indicates that the touch is cached for 15s after use (valid from YubiKey 4.3).
	CachedTouch
)

// Usage is an integer that indicates the limitation of the cert usage.
// It is used to restrict the sudo permission on some headless style certificates.
type Usage int

const (
	// AllUsage is the default value of usage for now, and it indicates the certificate provides both SSH and Sudo permissions.
	AllUsage Usage = iota
	// SSHOnlyUsage indicates the certificate provides SSH permission only.
	SSHOnlyUsage
)

var policies = map[TouchPolicy]string{
	DefaultTouch: "default",
	NeverTouch:   "never",
	AlwaysTouch:  "always",
	CachedTouch:  "cached",
}

// String() returns the name of the given policy.
func (policy TouchPolicy) String() string {
	return policies[policy]
}

// currently encoding/json package does not provide a `required` field tag,
// so manual sanity check is performed.
// more info: https://github.com/golang/go/issues/17163
var version2RequiredKeys = map[uint16][]string{
	1: {"prins", "transID", "reqUser", "reqIP", "reqHost", "isFirefighter", "isHWKey", "isHeadless", "isNonce", "touchPolicy", "ver"},
}

var version2SanityChecker = map[uint16]func(*KeyID) error{
	1: func(id *KeyID) error {
		err := sanityCheckerHeadless(id)
		if err != nil {
			return err
		}
		return sanityCheckerNonce(id)
	},
}

var noSanityCheck = func(*KeyID) error {
	return nil
}

// KeyID contains all the fields in key ID.
type KeyID struct {
	Principals []string `json:"prins"`
	TransID    string   `json:"transID"`
	ReqUser    string   `json:"reqUser"`
	ReqIP      string   `json:"reqIP"`
	ReqHost    string   `json:"reqHost"`
	// IsFirefighter indicates whether the certificate is for emergency situation.
	IsFirefighter bool `json:"isFirefighter"`
	// IsHWKey indicates whether the certificate has the key backed in the hardware (yubikey).
	IsHWKey bool `json:"isHWKey"`
	// IsHeadless indicates whether the certificate is provisioned for CI/CD pipelines.
	IsHeadless bool `json:"isHeadless"`
	// IsNonce indicates whether the certificate is regarded as a one-time certificate-based token.
	IsNonce     bool `json:"isNonce"`
	Usage       `json:"usage"`
	TouchPolicy `json:"touchPolicy"`
	Version     uint16 `json:"ver"`
}

// Marshal encodes keyID to a string.
func (kid *KeyID) Marshal() (string, error) {
	sanityChecker, ok := version2SanityChecker[kid.Version]
	if !ok {
		return "", fmt.Errorf(MsgUnsupportedVersion, kid.Version)
	}
	if err := sanityChecker(kid); err != nil {
		return "", err
	}

	kidBytes, err := json.Marshal(kid)
	if err != nil {
		return "", fmt.Errorf("failed to marshal keyid string: %v", err)
	}
	return string(kidBytes), nil
}

// Unmarshal decodes the input string to a KeyID struct.
func Unmarshal(kidStr string) (*KeyID, error) {
	kid := &KeyID{}
	kidBytes := []byte(kidStr)
	err := json.Unmarshal(kidBytes, kid)
	if err != nil {
		return nil, fmt.Errorf("fail to unmarshal keyid string: %v", err)
	}

	requiredKeys, ok := version2RequiredKeys[kid.Version]
	if !ok {
		return nil, fmt.Errorf(MsgUnsupportedVersion, kid.Version)
	}
	m := make(map[string]interface{})
	err = json.Unmarshal(kidBytes, &m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal keyid string to map: %v", err)
	}
	for _, key := range requiredKeys {
		if _, ok := m[key]; !ok {
			return nil, fmt.Errorf("missing key in keyid string: %s", key)
		}
	}

	sanityChecker, ok := version2SanityChecker[kid.Version]
	if !ok {
		return nil, fmt.Errorf(MsgUnsupportedVersion, kid.Version)
	}
	if err := sanityChecker(kid); err != nil {
		return nil, err
	}

	return kid, nil
}

// Clone returns a clone of the specified keyID.
func Clone(k *KeyID) *KeyID {
	kid := *k
	kid.Principals = make([]string, len(k.Principals))
	copy(kid.Principals, k.Principals)
	return &kid
}

// SetHumanUser updates the KeyID to be a human user KeyID.
func (kid *KeyID) SetHumanUser() {
	kid.IsHeadless = false
}

// GetProperty returns the string value of a property looked up by the given name.
// Package pam-sshca relies on the fields in KeyID. We don't want to update the pam-sshca and modify the config file
// on destination hosts everytime when there are any changes to the key id format (e.g. json tags).
// Hence we extract the value of the property by switch cases here.
func (kid *KeyID) GetProperty(name string) string {
	switch name {
	case "touchPolicy":
		return fmt.Sprintf("%d", kid.TouchPolicy)
	case "prins":
		return fmt.Sprintf("%v", kid.Principals)
	case "headless":
		return fmt.Sprintf("%v", kid.IsHeadless)
	default:
		return ""
	}
}

func sanityCheckerHeadless(k *KeyID) error {
	if !k.IsHeadless {
		return nil
	}
	if k.IsHWKey {
		return fmt.Errorf("conflict: IsHeadless and IsHWKey are both true")
	}
	if k.IsFirefighter {
		return fmt.Errorf("conflict: IsHeadless and IsFireFighter are both true")
	}
	if k.TouchPolicy != NeverTouch {
		return fmt.Errorf("conflict: IsHeadless is true and TouchPolicy is not NeverTouch")
	}
	return nil
}

func sanityCheckerNonce(k *KeyID) error {
	if !k.IsNonce {
		return nil
	}
	if k.IsFirefighter {
		return fmt.Errorf("conflict: IsNonce and IsFireFighter are both true")
	}
	if k.IsHeadless {
		return fmt.Errorf("conflict: IsNonce and IsHeadless are both true")
	}
	if k.TouchPolicy != NeverTouch {
		return fmt.Errorf("conflict: IsNonce is true and TouchPolicy is not NeverTouch")
	}
	return nil
}
