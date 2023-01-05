// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package authn_slot_attest

import (
	"fmt"

	"github.com/theparanoids/ysshra/agent/ssh"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/modules"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// Name is a unique name to identify an authentication module.
	Name = "slot_attest"
)

type authn struct {
	slotAgent *yubiagent.SlotAgent
	conf      *conf
}

// New returns an authentication module.
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
		slotAgent: slotAgent,
		conf:      conf,
	}, nil
}

// Authenticate attests a key slot to verify the key pair of that slot is generated inside a smartcard.
func (a *authn) Authenticate(_ *csr.ReqParam) error {
	// Read the certificate in the yubikey f9 slot.
	// F9 slot is only used for attestation of other keys generated on device with instruction f9.
	f9Cert, err := a.slotAgent.Agent().ReadSlot("f9")
	if err != nil {
		return fmt.Errorf(`failed to read slot f9, %v`, err)
	}

	attestor, err := yubiattest.NewAttestor(a.conf.PIVRootCA, a.conf.U2FRootCA)
	if err != nil {
		return fmt.Errorf(`failed to initialize yubikey attestor, %v`, err)
	}

	if err := attestor.Attest(f9Cert, a.slotAgent.AttestCert()); err != nil {
		return fmt.Errorf(`failed to attest yubikey slot %s, %v`, a.slotAgent.SlotCode(), err)
	}

	if err = ssh.ChallengeSSHAgent(a.slotAgent.Agent(), a.slotAgent.PublicKey()); err != nil {
		return fmt.Errorf(`failed to authenticate slot key %s with challenge response, %v"`, a.slotAgent.SlotCode(), err)
	}

	return nil
}
