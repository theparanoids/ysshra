package csr_smartcard_hardkey

import (
	"fmt"

	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/crypki"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/modules"
	"github.com/theparanoids/ysshra/sshutils/cert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	Name = "smartcard_hardkey"
)

type generator struct {
	slotAgent *yubiagent.SlotAgent
	c         *conf
	opt       *modules.CSROption
}

func New(ag agent.Agent, c map[string]interface{}, opt *modules.CSROption) (modules.CSRModule, error) {
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

	return &generator{
		slotAgent: slotAgent,
		c:         conf,
		opt:       opt,
	}, nil
}

func (g *generator) Generate(param *csr.ReqParam) ([]csr.AgentKey, error) {
	keyIdentifier, ok := g.opt.KeyIdentifiers[param.Attrs.CAPubKeyAlgo]
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
		Version:       g.opt.KeyIDVersion,
		IsFirefighter: g.c.IsFirefighter,
		IsHWKey:       true,
		IsHeadless:    false,
		IsNonce:       false,
		Usage:         keyid.AllUsage,
		TouchPolicy:   keyid.TouchPolicy(g.c.TouchPolicy),
	}

	request := &proto.SSHCertificateSigningRequest{
		KeyMeta:    &proto.KeyMeta{Identifier: keyIdentifier},
		Extensions: crypki.GetDefaultExtension(),
		Validity:   g.c.CertValiditySec,
		Principals: kid.Principals,
		PublicKey:  string(ssh.MarshalAuthorizedKey(g.slotAgent.PublicKey())),
	}

	var err error
	request.KeyId, err = kid.Marshal()
	if err != nil {
		return nil, err
	}
	g.slotAgent.RegisterCSR(request)
	return []csr.AgentKey{g.slotAgent}, nil
}
