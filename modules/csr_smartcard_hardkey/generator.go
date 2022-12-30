package csr_smartcard_hardkey

import (
	"errors"
	"fmt"

	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/crypki"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/sshutils/cert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type generator struct {
	c *conf
}

func (g *generator) generate(agent agent.Agent, param *csr.ReqParam) ([]*proto.SSHCertificateSigningRequest, error) {
	ag, ok := agent.(yubiagent.YubiAgent)
	if !ok {
		return nil, errors.New("only yubiagent is supported to generate the CSR")
	}

	keyIdentifier, ok := g.c.KeyIdentifiers[param.Attrs.CAPubKeyAlgo]
	if !ok {
		return nil, fmt.Errorf("unsupported CA public key algorithm %q", param.Attrs.CAPubKeyAlgo)
	}

	principals := cert.GetPrincipals(g.c.Principals, param.LogName)

	kid := &keyid.KeyID{
		Principals:    principals,
		TransID:       param.TransID,
		ReqUser:       param.ReqUser,
		ReqIP:         param.ClientIP,
		ReqHost:       param.ReqHost,
		Version:       g.c.KeyIDVer,
		IsFirefighter: g.c.IsFirefighter,
		IsHWKey:       g.c.IsHWKey,
		IsHeadless:    false,
		IsNonce:       false,
		Usage:         keyid.AllUsage,
		TouchPolicy:   keyid.TouchPolicy(g.c.TouchPolicy),
	}

	keySlot, err := yubiagent.NewSlotAgent(ag, g.c.Slot)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key slot %s from the agent", g.c.Slot)
	}

	request := &proto.SSHCertificateSigningRequest{
		KeyMeta:    &proto.KeyMeta{Identifier: keyIdentifier},
		Extensions: crypki.GetDefaultExtension(),
		Validity:   g.c.CertValiditySec,
		Principals: kid.Principals,
		PublicKey:  string(ssh.MarshalAuthorizedKey(keySlot.PublicKey())),
	}

	request.KeyId, err = kid.Marshal()
	if err != nil {
		return nil, err
	}
	return []*proto.SSHCertificateSigningRequest{request}, nil
}
