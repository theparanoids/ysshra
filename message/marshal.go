package message

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	// TODO: cleanup following hardcoded attributes once we upgrade the gensign IFVer to 7.
	requesterAttr          = "req"
	hardKeyAttr            = "HardKey"
	touch2SSHAttr          = "Touch2SSH"
	githubAttr             = "github"
	isFirefighterAttr      = "IsFirefighter"
	touchlessSudoHostsAttr = "TouchlessSudoHosts"
	touchlessSudoTimeAttr  = "TouchlessSudoTime"
	sshClientVersionAttr   = "SSHClientVersion"
)

// Marshal converts an *Attributes to a json string.
// It guarantees the output fields are all valid in format when error is nil.
func (a *Attributes) Marshal() (string, error) {
	err := a.sanityCheck()
	if err != nil {
		return "", fmt.Errorf("gensign attributes sanity check failed, err: %v", err)
	}

	if a.IfVer < 7 {
		return a.MarshalLegacy()
	}

	attrBtyes, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("failed to marshal sshra gensign attributes: %v", err)
	}
	return string(attrBtyes), nil
}

// Unmarshal converts an SSH arg string to an *Attributes.
// It guarantees the output fields are all valid in format when error is nil.
func Unmarshal(attrsStr string) (*Attributes, error) {
	if strings.Contains(attrsStr, legacyInterfaceVersion) {
		return UnmarshalLegacy(attrsStr)
	}
	attrs := &Attributes{}
	kidBytes := []byte(attrsStr)
	err := json.Unmarshal(kidBytes, attrs)
	if err != nil {
		return nil, fmt.Errorf("fail to unmarshal attributes string: %v", err)
	}
	return attrs, nil
}

// MarshalLegacy converts an *Attributes to a legacy SSH arg string that concatenated by space.
// It guarantees the output fields are all valid in format when error is nil.
// TODO: cleanup MarshalLegacy once we upgrade the gensign IFVer to 7.
func (a *Attributes) MarshalLegacy() (string, error) {
	cmdArgs := []string{legacyInterfaceVersion}
	cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", sshClientVersionAttr, a.SSHClientVersion))
	cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s@%s", requesterAttr, a.Username, a.Hostname))
	if a.HardKey {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", hardKeyAttr, a.HardKey))
	}
	if a.Touch2SSH {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", touch2SSHAttr, a.Touch2SSH))
	}
	// Client >= 2.5.1 should always pass github= argument so server can tell it's newer version
	cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", githubAttr, a.Github))

	if a.TouchlessSudo != nil {
		if a.TouchlessSudo.IsFirefighter {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", isFirefighterAttr, a.TouchlessSudo.IsFirefighter))
		}
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", touchlessSudoHostsAttr, a.TouchlessSudo.TouchlessSudoHosts))
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%d", touchlessSudoTimeAttr, int(a.TouchlessSudo.TouchlessSudoTime)))
	}

	return strings.Join(cmdArgs, " "), nil
}

// UnmarshalLegacy converts a legacy SSH arg string to an *Attributes.
// It guarantees the output fields are all valid in format when error is nil.
// TODO: cleanup UnmarshalLegacy once we upgrade the gensign IFVer to 7.
func UnmarshalLegacy(attrsStr string) (*Attributes, error) {
	attrs := parseAttrs(attrsStr)

	a := &Attributes{}
	// TODO: Return error when ssh client version is empty. Now not every client sends this attribute.
	a.SSHClientVersion = attrs[sshClientVersionAttr]

	requester, ok := attrs[requesterAttr]
	if !ok {
		return nil, fmt.Errorf(`cannot find requester field %q`, requesterAttr)
	}
	// A valid requester field should looks like: username@hostname.
	fields := strings.Split(requester, "@")
	if len(fields) != 2 {
		return nil, fmt.Errorf(`invalid requester format: %s`, requester)
	}
	a.Username = fields[0]
	a.Hostname = fields[1]

	if _, ok := attrs[hardKeyAttr]; ok {
		a.HardKey = true
	}

	if _, ok := attrs[touch2SSHAttr]; ok {
		a.Touch2SSH = true
	}

	var err error
	if a.Github, err = strconv.ParseBool(attrs[githubAttr]); err != nil {
		return nil, err
	}

	// TODO: marshal touchless sudo fields

	return a, nil
}

func parseAttrs(attrsStr string) map[string]string {
	attrs := map[string]string{}
	attributes := strings.Split(attrsStr, " ")
	for _, attribute := range attributes {
		attribute = strings.TrimSpace(attribute)
		if attribute == "" {
			continue
		}
		var key, value string
		if sep := strings.Index(attribute, "="); sep == -1 {
			key, value = attribute, ""
		} else {
			key, value = attribute[:sep], attribute[sep+1:]
		}
		attrs[key] = value
	}
	return attrs
}
