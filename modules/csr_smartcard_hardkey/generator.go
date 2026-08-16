// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr_smartcard_hardkey

import (
	"fmt"

	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/agent/yubiagent"
	yconfig "github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/crypki"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/modules"
	"github.com/theparanoids/ysshra/sshutils/cert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// Name is a unique name to identify a CSR generator module.
	Name = "smartcard_hardkey"
)

type generator struct {
	slot *yubiagent.Slot
	c    *config
	opt  *modules.CSROption
}

// New returns a CSR generator module.
func New(ag agent.Agent, c map[string]interface{}, opt *modules.CSROption) (modules.CSRModule, error) {
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

	return &generator{
		slot: slot,
		c:    conf,
		opt:  opt,
	}, nil
}

// Generate generates a slice of agent keys which include SSH certificate requests.
func (g *generator) Generate(param *csr.ReqParam) ([]csr.AgentKey, error) {
	keyIdentifier, ok := g.opt.KeyIdentifiers[param.Attrs.CAPubKeyAlgo]
	if !ok {
		return nil, fmt.Errorf("unsupported CA public key algorithm %q", param.Attrs.CAPubKeyAlgo)
	}

	principals := cert.GetPrincipals(g.c.PrincipalsTpl, param.LogName)

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
		PublicKey:  string(ssh.MarshalAuthorizedKey(g.slot.PublicKey())),
	}

	var err error
	request.KeyId, err = kid.Marshal()
	if err != nil {
		return nil, err
	}
	g.slot.RegisterCSR(request)
	return []csr.AgentKey{g.slot}, nil
}
