package csr_smartcard_touch

import (
	"fmt"

	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/keyid"
)

type generator struct{}

func (g *generator) processRegularCerts(request *proto.SSHCertificateSigningRequest, kid keyid.KeyID, options *module.Options) (err error) {
	// if request needs to be modified, clone it and then modify the clone
	reqC, _ := gproto.Clone(request).(*proto.SSHCertificateSigningRequest)
	reqC.Principals = m.getPrincipals(reqC, touchCert, options.Attrs.Touch2SSH)
	kid.Principals = reqC.Principals
	reqC.KeyId, err = kid.Marshal()
	if err != nil {
		return err
	}

	// sign touch certificate
	touchCerts, com, err := m.getTouchCert(reqC, kid, m.touchSlot)
	if err != nil {
		return fmt.Errorf(`msg="%s", err="%v"`, module.MsgFailedSignCerts, err)
	}
	appendCerts(touchCerts, com)

	// sign firefighter certificate
	fireFighterCerts, com, err := m.getFirefighterCert(reqC, kid, m.touchSlot)
	if err != nil {
		return fmt.Errorf(`msg="%s", err="%v"`, module.MsgFailedSignCerts, err)
	}
	appendCerts(fireFighterCerts, com)

	// for regular touchless certificate change principals of "special users"
	// to user:notouch. E.g. if the user `dfsuther` should be provisioned ":notouch" certificate
	// then change his principal to `dfsuther:notouch` for touchless cert.
	reqC, _ = gproto.Clone(request).(*proto.SSHCertificateSigningRequest)
	reqC.Principals = m.getPrincipals(reqC, touchlessCert, options.Attrs.Touch2SSH)
	kid.Principals = reqC.Principals
	reqC.KeyId, err = kid.Marshal()
	if err != nil {
		return err
	}

	// sign regular touchless certificates
	touchlessCerts, com, err := m.getTouchlessCert(reqC, kid, m.touchlessSlot, regularCertValidity)
	if err != nil {
		return fmt.Errorf(`msg="%s", err="%v"`, module.MsgFailedSignCerts, err)
	}
	appendCerts(touchlessCerts, com)

	// Purge certificates from ssh-agent.
	if err := agent.RemoveUserCertFromSSHAgent(); err != nil {
		return fmt.Errorf(`msg="%s", err="%v"`, module.MsgFailedRemoveCerts, err)
	}

	// Publish certificates to client.
	if err := addUserCertToYubicoAgent(certs, comments); err != nil {
		return fmt.Errorf(`msg="%s", err="%v"`, module.MsgFailedPublishCerts, err)
	}
	module.PrintCertsWithDelimiter("hardcert", touchlessCerts)
	module.PrintCertsWithDelimiter("hardtouchcert", touchCerts)
	module.PrintCertsWithDelimiter("firefightercert", fireFighterCerts)

	return nil
}

