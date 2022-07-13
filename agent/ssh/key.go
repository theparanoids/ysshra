// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package ssh

import (
	"fmt"

	"github.com/theparanoids/ysshura/sshutils/key"
	"golang.org/x/crypto/ssh"
	ag "golang.org/x/crypto/ssh/agent"
)

// ListKeys returns all the keys filtered.
func ListKeys(agent ag.Agent, filter keyFilter) ([]ag.Key, error) {
	keys, err := agent.List()
	if err != nil {
		return nil, err
	}
	var filteredKeys []ag.Key
	for _, k := range keys {
		if filter(k) {
			filteredKeys = append(filteredKeys, *k)
		}
	}
	return filteredKeys, nil
}

// AgentKey represents an SSH key pair in ssh-agent.
// It also stores the CSRs of the key pair.
type AgentKey struct {
	agent    ag.Agent
	addedKey ag.AddedKey
	pubKey   ssh.PublicKey
	opt      KeyOpt
}

// NewSSHAgentKey initializes an SSHAgentKey from the network connection.
func NewSSHAgentKey(agent ag.Agent) (*AgentKey, error) {
	return NewSSHAgentKeyWithOpt(agent, DefaultKeyOpt)
}

// NewSSHAgentKeyWithOpt initializes an AgentKey from the network connection and the opt.
func NewSSHAgentKeyWithOpt(agent ag.Agent, opt KeyOpt) (*AgentKey, error) {
	priv, pub, err := key.GenerateKeyPair(opt.PublicKeyAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to genreate key pair, err: %v", err)
	}

	addedKey := ag.AddedKey{
		PrivateKey:   priv,
		LifetimeSecs: opt.PrivateKeyValiditySec,
		Comment:      opt.PrivateKeyLabel,
	}
	if err := agent.Add(addedKey); err != nil {
		return nil, fmt.Errorf("failed to insert new private key to agent, err: %v", err)
	}

	return &AgentKey{
		agent:    agent,
		pubKey:   pub,
		addedKey: addedKey,
		opt:      opt,
	}, nil
}

// AddCertsToAgent add the certificates to ssh agent.
func (a *AgentKey) AddCertsToAgent(certs []ssh.PublicKey, comments []string) error {
	if err := a.refreshKeys(); err != nil {
		return err
	}

	var err error
	addedKey := a.addedKey
	for i, cert := range certs {
		addedKey.Certificate, err = key.CastSSHPublicKeyToCertificate(cert)
		if addedKey.Certificate == nil || err != nil {
			continue
		}
		addedKey.Comment = a.opt.CertLabel
		if len(comments) > i && comments[i] != "" {
			a.addedKey.Comment += fmt.Sprintf("%s-%s", a.addedKey.Comment, comments[i])
		}
		if err := a.agent.Add(addedKey); err != nil {
			return err
		}
	}
	return nil
}

// PublicKey returns the public key of the agent key.
func (a *AgentKey) PublicKey() ssh.PublicKey {
	return a.pubKey
}

// refreshKeys removes the target keys from ssh agent.
func (a *AgentKey) refreshKeys() error {
	keys, err := a.agent.List()
	if err != nil {
		return err
	}
	for _, k := range keys {
		if a.opt.KeyRefreshFilter(k) {
			if err := a.agent.Remove(k); err != nil {
				return err
			}
		}
	}
	return nil
}
