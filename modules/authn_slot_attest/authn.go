package authn_slot_attest

import (
	"fmt"

	"github.com/theparanoids/ysshra/agent/ssh"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/attestation/yubiattest"
	"github.com/theparanoids/ysshra/csr"
)

type authn struct {
	slot      string
	pivRootCA string
	u2fRootCa string
}

func (a *authn) authenticate(slot *yubiagent.SlotAgent, _ *csr.ReqParam) error {
	// Read the certificate in the yubikey f9 slot.
	// F9 slot is only used for attestation of other keys generated on device with instruction f9.
	f9Cert, err := slot.Agent().ReadSlot("f9")
	if err != nil {
		return fmt.Errorf(`failed to read slot f9, %v`, err)
	}

	attestor, err := yubiattest.NewAttestor(a.pivRootCA, a.u2fRootCa)
	if err != nil {
		return fmt.Errorf(`failed to initialize yubikey attestor, %v`, err)
	}

	if err := attestor.Attest(f9Cert, slot.AttestCert()); err != nil {
		return fmt.Errorf(`failed to attest yubikey slot %s, %v`, a.slot, err)
	}

	if err = ssh.ChallengeSSHAgent(slot.Agent(), slot.PublicKey()); err != nil {
		return fmt.Errorf(`failed to authenticate slot key %s with challenge response, %v"`, a.slot, err)
	}

	return nil
}
