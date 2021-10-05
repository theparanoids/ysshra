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
	sshClientVersion       = "SSHClientVersion"
)

func Marshal(m *Attributes) (string, error) {
	cmdArgs := []string{interfaceVersion}
	if m.Username == "" {
		return "", errors.New("user name cannot be empty")
	}
	if m.Hostname == "" {
		return "", errors.New("host name cannot be empty")
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s@%s", requesterAttr, m.Username, m.Hostname))
	if m.HardKey {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", hardKeyAttr, m.HardKey))
	}
	if m.Touch2SSH {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", touch2SSHAttr, m.Touch2SSH))
	}
	// Client >= 2.5.1 should always pass github= argument so server can tell it's newer version
	cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", githubAttr, m.Github))

	if m.TouchlessSudo != nil {
		if m.TouchlessSudo.IsFirefighter {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", isFirefighterAttr, m.TouchlessSudo.IsFirefighter))
		}
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", touchlessSudoHostsAttr, m.TouchlessSudo.TouchlessSudoHosts))
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%d", touchlessSudoTimeAttr, int(m.TouchlessSudo.TouchlessSudoTime.Minutes())))
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", sshClientVersion, m.TouchlessSudo.SSHClientVersion))
	}

	return strings.Join(cmdArgs, " "), nil
}

func Unmarshal(argsStr string) (*Attributes, error) {
	m := &Attributes{}
	attrs := parseAttrs(argsStr)

	requester, ok := attrs[requesterAttr]
	if !ok {
		return nil, fmt.Errorf(`cannot find requester field %q`, requesterAttr)
	}
	// A valid requester field should looks like: username@hostname.
	fields := strings.Split(requester, "@")
	if len(fields) != 2 {
		return nil, fmt.Errorf(`invalid requester format: %s`, requester)
	}
	m.Username = fields[0]
	m.Hostname = fields[1]

	if _, ok := attrs[hardKeyAttr]; ok {
		m.HardKey = true
	}

	if _, ok := attrs[touch2SSHAttr]; ok {
		m.Touch2SSH = true
	}

	var err error
	if m.Github, err = strconv.ParseBool(attrs[githubAttr]); err != nil {
		return nil, err
	}

	// TODO: marshal touchless sudo fields

	return m, nil
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
