package version

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	base    = 10
	bitSize = 16
)

var (
	versionRE = regexp.MustCompile(`^\d+\.\d+$`)
)

// Version is currently used to represent OpenSSH version.
// patch version can be added in the future if needed.
type Version struct {
	major, minor uint16
}

// New initialized a Version
func New(major, minor uint16) Version {
	return Version{
		major: major,
		minor: minor,
	}
}

// NewDefaultVersion returns a Version with all version numbers set to zero.
func NewDefaultVersion() Version {
	return Version{major: 0, minor: 0}
}

// Marshal encodes Version to string, e.g. "8.0"
func (v Version) Marshal() string {
	return fmt.Sprintf("%d.%d", v.major, v.minor)
}

// Unmarshal parses a string to Version.
func Unmarshal(s string) (Version, error) {
	if !versionRE.MatchString(s) {
		return NewDefaultVersion(), errors.New(`invalid format, expected "major.minor", e.g. "8.0"`)
	}
	i := strings.Index(s, ".")
	major, err := strconv.ParseUint(s[:i], base, bitSize)
	if err != nil {
		return NewDefaultVersion(), err
	}
	minor, err := strconv.ParseUint(s[i+1:], base, bitSize)
	if err != nil {
		return NewDefaultVersion(), err
	}
	return New(uint16(major), uint16(minor)), nil
}

// LessThan checks if this version is released earlier than the other version.
func (v Version) LessThan(other Version) bool {
	return v.major < other.major ||
		(v.major == other.major && v.minor < other.minor)
}
