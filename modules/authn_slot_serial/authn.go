package authn_slot_serial

import (
	"fmt"
	"os"
	"strings"

	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/modules"
	"golang.org/x/crypto/ssh/agent"
)

const (
	Name = "slot_serial"
)

type authn struct {
	slotAgent       *yubiagent.SlotAgent
	yubikeyMappings string
}

func New(ag agent.Agent, c map[string]interface{}) (modules.AuthnModule, error) {
	conf := &conf{}
	if err := config.ExtractModuleConf(c, conf); err != nil {
		return nil, fmt.Errorf("failed to initilaize module %q, %v", Name, err)
	}

	yubiAgent, ok := ag.(yubiagent.YubiAgent)
	if !ok {
		return nil, fmt.Errorf("yubiagent is the only supported agent in module %q", Name)
	}

	slotAgent, err := yubiagent.NewSlotAgent(yubiAgent, conf.Slot)
	if err != nil {
		return nil, fmt.Errorf("failed to access slot agent in module %q, %v", Name, err)
	}

	return &authn{
		slotAgent:       slotAgent,
		yubikeyMappings: conf.YubikeyMappings,
	}, nil

}

func (a *authn) Authenticate(param *csr.ReqParam) error {
	// Look up the yubikey serial number from the attestation cert.
	serial, err := yubiattest.ModHex(a.slotAgent.AttestCert())
	if err != nil {
		return fmt.Errorf(`failed to lookup the current yubiKey serial number in the attestation cert at slot %s, %v"`, a.slotAgent.SlotCode(), err)
	}

	user, err := findUserFromYubikeyMapping(serial, a.yubikeyMappings)
	if err != nil {
		return fmt.Errorf(`failed to find username in the yubikey mapping by serial %s, %v"`, serial, err)
	}

	if user != param.LogName {
		return fmt.Errorf(`yubikey doesn't belong to current user, serial: %s, yubikey owner: %s`, serial, user)
	}

	return nil
}

// findUserFromYubikeyMapping searches for the username in the yubiKey mapping file
// using the given yubikey serial number.
func findUserFromYubikeyMapping(modhex, mapping string) (user string, err error) {
	data, err := os.ReadFile(mapping)
	if err != nil {
		return "", err
	}

	if len(modhex) != 8 {
		return "", fmt.Errorf("invalid modhex value %v. must be 8 characters exactly", modhex)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		user := fields[0]
		keys := fields[1:]
		for _, key := range keys {
			if key[4:] == modhex {
				return user, nil
			}
		}
	}
	return "", fmt.Errorf("user not found")
}
