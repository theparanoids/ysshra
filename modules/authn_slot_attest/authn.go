// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_slot_attest

import (
	"fmt"

	"github.com/theparanoids/ysshra/agent/ssh"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	yconfig "github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/modules"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// Name is a unique name to identify an authentication module.
	Name = "slot_attest"
)

type authn struct {
	slot *yubiagent.Slot
	conf *config
}

// New returns an authentication module.
func New(ag agent.Agent, c map[string]interface{}) (modules.AuthnModule, error) {
	conf := &config{}
	if err := yconfig.DecodeModuleConfig(c, conf); err != nil {
		return nil, fmt.Errorf("failed to initilaize module %q, %v", Name, err)
	}

	yubiAgent, ok := ag.(yubiagent.YubiAgent)
	if !ok {
		return nil, fmt.Errorf("yubiagent is the only supported agent in module %q", Name)
	}

	slot, err := yubiagent.NewSlot(yubiAgent, conf.Slot)
	if err != nil {
		return nil, fmt.Errorf("failed to access slot agent in module %q, %v", Name, err)
	}

	return &authn{
		slot: slot,
		conf: conf,
	}, nil
}

// Authenticate attests a key slot to verify the key pair of that slot is generated inside a smartcard.
func (a *authn) Authenticate(_ *csr.ReqParam) error {
	// Read the certificate in the yubikey f9 slot.
	// F9 slot is only used for attestation of other keys generated on device with instruction f9.
	f9Cert, err := a.slot.Agent().ReadSlot("f9")
	if err != nil {
		return fmt.Errorf(`failed to read slot f9, %v`, err)
	}

	attestor, err := yubiattest.NewAttestor(a.conf.PIVRootCA, a.conf.U2FRootCA)
	if err != nil {
		return fmt.Errorf(`failed to initialize yubikey attestor, %v`, err)
	}

	if err := attestor.Attest(f9Cert, a.slot.AttestCert()); err != nil {
		return fmt.Errorf(`failed to attest yubikey slot %s, %v`, a.slot.SlotCode(), err)
	}

	if err = ssh.ChallengeSSHAgent(a.slot.Agent(), a.slot.PublicKey()); err != nil {
		return fmt.Errorf(`failed to authenticate slot key %s with challenge response, %v"`, a.slot.SlotCode(), err)
	}

	return nil
}
