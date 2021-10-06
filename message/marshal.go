package message

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	requesterAttr          = "req"
	hardKeyAttr            = "HardKey"
	touch2SSHAttr          = "Touch2SSH"
	githubAttr             = "github"
	isFirefighterAttr      = "IsFirefighter"
	touchlessSudoHostsAttr = "TouchlessSudoHosts"
	touchlessSudoTimeAttr  = "TouchlessSudoTime"
	sshClientVersionAttr   = "SSHClientVersion"
)

// Marshal converts an *Attributes to a string.
// It guarantees the output fields are all valid in format when error is nil.
func Marshal(a *Attributes) (string, error) {
	cmdArgs := []string{interfaceVersion}
	if a.SSHClientVersion == "" {
		return "", errors.New("ssh client version cannot be empty")
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", sshClientVersionAttr, a.SSHClientVersion))
	if a.Username == "" {
		return "", errors.New("user name cannot be empty")
	}
	if a.Hostname == "" {
		return "", errors.New("host name cannot be empty")
	}
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
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%d", touchlessSudoTimeAttr, int(a.TouchlessSudo.TouchlessSudoTime.Minutes())))
	}

	return strings.Join(cmdArgs, " "), nil
}

// Unmarshal converts a string to an *Attributes.
// It guarantees the output fields are all valid in format when error is nil.
func Unmarshal(attrsStr string) (*Attributes, error) {
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
