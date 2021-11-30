package message

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	// TODO: cleanup following hardcoded attributes once we upgrade the gensign IFVer to 7.
	ifVerAttr              = "IFVer"
	requesterAttr          = "req"
	hardKeyAttr            = "HardKey"
	touch2SSHAttr          = "Touch2SSH"
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

	// TODO: cleanup MarshalLegacy once we upgrade the gensign IFVer to 7.
	if a.IfVer < 7 {
		return a.MarshalLegacy()
	}

	attrBytes, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("failed to marshal sshra gensign attributes: %v", err)
	}
	return string(attrBytes), nil
}

// Unmarshal converts an SSH arg string to an *Attributes.
// It guarantees the output fields are all valid in format when error is nil.
func Unmarshal(attrsStr string) (*Attributes, error) {
	attrs := &Attributes{}
	if err := json.Unmarshal([]byte(attrsStr), &attrs); err != nil {
		// TODO: cleanup UnmarshalLegacy once we upgrade the gensign IFVer to 7.
		return UnmarshalLegacy(attrsStr)
	}
	err := attrs.sanityCheck()
	if err != nil {
		return nil, fmt.Errorf("gensign attributes sanity check failed, err: %v", err)
	}
	attrs.populate()
	return attrs, nil
}

// ExtendedAttr looks up the value of the key from the extended attributes.
func (a *Attributes) ExtendedAttr(key string) (interface{}, error) {
	val, ok := a.Exts[key]
	if ok {
		return val, nil
	}
	// TODO: remove following case insensitive key comparison once we upgrade the gensign IFVer to 7.
	for extKey, extVal := range a.Exts {
		if strings.EqualFold(extKey, key) {
			return extVal, nil
		}
	}
	return nil, fmt.Errorf("%v not found in the extended attributes", key)
}

// ExtendedAttrStr looks up the value of the key from the extended attributes.
// Return the value in string type.
func (a *Attributes) ExtendedAttrStr(key string) (string, error) {
	attr, _ := a.ExtendedAttr(key)
	str, ok := attr.(string)
	if !ok {
		return "", fmt.Errorf("string for %v not found in the extended attributes", key)
	}
	return str, nil
}

// ExtendedAttrBool looks up the value of the key from the extended attributes.
// Return the value in bool type.
func (a *Attributes) ExtendedAttrBool(key string) (bool, error) {
	attr, err := a.ExtendedAttr(key)
	if err != nil {
		return false, err
	}
	b, ok := attr.(bool)
	if ok {
		return b, nil
	}
	str, ok := attr.(string)
	if ok {
		return strconv.ParseBool(str)
	}
	return false, fmt.Errorf("value of %v in the extended attributes is not bool type, got %v", key, attr)
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

	if a.TouchlessSudo != nil {
		if a.TouchlessSudo.IsFirefighter {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%v", isFirefighterAttr, a.TouchlessSudo.IsFirefighter))
		}
		if len(a.TouchlessSudo.Hosts) != 0 {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", touchlessSudoHostsAttr, a.TouchlessSudo.Hosts))
		}
		if a.TouchlessSudo.Time != 0 {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%d", touchlessSudoTimeAttr, int(a.TouchlessSudo.Time)))
		}
	}

	return strings.Join(cmdArgs, " "), nil
}

// UnmarshalLegacy converts a legacy SSH arg string to an *Attributes.
// It guarantees the output fields are all valid in format when error is nil.
// TODO: cleanup UnmarshalLegacy once we upgrade the gensign IFVer to 7.
func UnmarshalLegacy(attrsStr string) (*Attributes, error) {
	attrs := parseAttrsLegacy(attrsStr)

	a := &Attributes{
		Exts: map[string]interface{}{},
	}

	if val, ok := attrs[ifVerAttr]; ok {
		a.IfVer, _ = strconv.Atoi(val)
	}

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

	if val, ok := attrs[hardKeyAttr]; ok {
		a.HardKey, _ = strconv.ParseBool(val)
	}

	if val, ok := attrs[touch2SSHAttr]; ok {
		a.Touch2SSH, _ = strconv.ParseBool(val)
	}

	t := &TouchlessSudo{}
	if val, ok := attrs[isFirefighterAttr]; ok {
		t.IsFirefighter, _ = strconv.ParseBool(val)
	}

	if val, ok := attrs[touchlessSudoHostsAttr]; ok {
		t.Hosts = val
	}

	if val, ok := attrs[touchlessSudoTimeAttr]; ok {
		t.Time, _ = strconv.ParseInt(val, 10, 0)
	}
	a.TouchlessSudo = t

	for key, val := range attrs {
		a.Exts[key] = val
	}

	return a, nil
}

// TODO: cleanup parseAttrsLegacy once we upgrade the gensign IFVer to 7.
func parseAttrsLegacy(attrsStr string) map[string]string {
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
