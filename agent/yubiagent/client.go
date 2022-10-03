// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/theparanoids/ysshra/agent/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type client struct {
	conn     net.Conn
	connLock sync.Mutex
	agent    agent.ExtendedAgent
}

// NewClient returns a new YubiAgent client object.
// The parameter address is used to connect to a YubiAgent server.
// The definition of address depends on OS.
// For Darwin and Linux, address is a unix socket.
// For Windows, address is a named pipe.
func NewClient(address string) (YubiAgent, error) {
	conn, err := utils.GetConn(address)
	if err != nil {
		return nil, err
	}
	return &client{
		conn:     conn,
		connLock: sync.Mutex{},
		agent:    agent.NewClient(conn),
	}, nil
}

// NewClientFromConn returns a new YubiAgent client object.
// This function can be used when we have an in-memory network connection net.Pipe()
// or an SSH agent connection.
func NewClientFromConn(c net.Conn) (YubiAgent, error) {
	if c == nil {
		return nil, errors.New("cannot create new client from empty net.Conn")
	}
	return &client{
		conn:     c,
		connLock: sync.Mutex{},
		agent:    agent.NewClient(c),
	}, nil
}

func (c *client) call(req []byte) (resp []byte, err error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	if err = write(c.conn, req); err != nil {
		return nil, err
	}
	return read(c.conn)
}

// Forward sends the request to the connection.
func (c *client) Forward(req []byte) (resp []byte, err error) {
	return c.call(req)
}

// AddHardCert adds a smartcard certificate into the agent server.
func (c *client) AddHardCert(key ssh.PublicKey, comment string) error {
	if key == nil {
		return errors.New("null key provided")
	}
	var msg = agentAddHardCertReq{
		KeyBlob: key.Marshal(),
		Comment: comment,
	}
	resp, err := c.call(ssh.Marshal(msg))
	if err != nil {
		return err
	}

	if string(resp) != "SUCCESS" {
		return errors.New(string(resp))
	}
	return nil
}

// ListSlots sends a list slots request to the agent server.
func (c *client) ListSlots() (slots []string, err error) {
	resp, err := c.call([]byte{AgentMessageListSlots})
	if err != nil {
		return nil, err
	}

	var msg agentListSlotsResp
	if err = ssh.Unmarshal(resp, &msg); err != nil {
		return nil, err
	}
	if msg.Err != "" {
		err = errors.New(msg.Err)
	}
	return msg.Slots, err
}

// ReadSlot sends a read slot request to the agent server.
func (c *client) ReadSlot(slot string) (cert *x509.Certificate, err error) {
	req := append([]byte{AgentMessageReadSlot}, []byte(slot)...)
	resp, err := c.call(req)
	if err != nil {
		return nil, err
	}

	var msg agentReadSlotResp
	if err = ssh.Unmarshal(resp, &msg); err != nil {
		return nil, err
	}
	if msg.Err != "" {
		return nil, errors.New(msg.Err)
	}
	return utils.ParsePEMCertificate(msg.Cert)
}

// AttestSlot sends an attest slog request to the agent server.
func (c *client) AttestSlot(slot string) (cert *x509.Certificate, err error) {
	req := append([]byte{AgentMessageAttestSlot}, []byte(slot)...)
	resp, err := c.call(req)
	if err != nil {
		return nil, err
	}

	var msg agentReadSlotResp
	if err = ssh.Unmarshal(resp, &msg); err != nil {
		return nil, err
	}
	if msg.Err != "" {
		return nil, errors.New(msg.Err)
	}
	return utils.ParsePEMCertificate(msg.Cert)
}

// Wait appends the AgentMessageWait message to the given request, and sends to agent server.
func (c *client) Wait(agentMsg byte) error {
	req := append([]byte{AgentMessageWait}, agentMsg)
	resp, err := c.call(req)
	if err != nil {
		return err
	}

	if string(resp) != "SUCCESS" {
		return errors.New(string(resp))
	}
	return nil
}

// AddSmartcardKey sends an add smartcard request to the agent server.
// Ref: https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.2.5
func (c *client) AddSmartcardKey(readerID string, pin []byte, lifetime time.Duration, confirmBeforeUse bool) error {
	var constraints []byte
	if lifetime != 0 {
		secs := uint32(lifetime.Seconds())
		constraints = append(constraints, ssh.Marshal(agentLifetimeConstraint{secs})...)
	}

	if confirmBeforeUse {
		constraints = append(constraints, agentConstrainConfirm)
	}

	req := ssh.Marshal(agentAddSmartcardKeyReq{
		ID:          readerID,
		PIN:         pin,
		Constraints: constraints,
	})

	resp, err := c.call(req)
	if err != nil {
		return err
	}

	if _, err := rand.Read(req); err != nil {
		return err
	}

	if len(resp) < 1 {
		return errors.New("yubiagent: empty packet")
	}
	if resp[0] != agentSuccess {
		return errors.New("yubiagent: could not add smartcard " + readerID + ": agent failure")
	}

	return nil
}

// RemoveSmartcardKey sends a remove smartcard key request to the agent server.
// Ref: https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.3
func (c *client) RemoveSmartcardKey(readerID string, pin []byte) error {
	req := ssh.Marshal(agentRemoveSmartcardKeyReq{
		ID:  readerID,
		PIN: pin,
	})

	resp, err := c.call(req)
	if err != nil {
		return err
	}

	if _, err := rand.Read(req); err != nil {
		return err
	}

	if len(resp) < 1 {
		return errors.New("yubiagent: empty packet")
	}
	if resp[0] != agentSuccess {
		return errors.New("yubiagent: could not remove smartcard " + readerID + ": agent failure")
	}

	return nil
}

// Close closes the connection to the agent server.
func (c *client) Close() error {
	return c.conn.Close()
}

// List lists all the agent keys from the agent server.
func (c *client) List() ([]*agent.Key, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.List()
}

// Sign signs the underlying data by the given key.
func (c *client) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	if key == nil {
		return nil, errors.New("null key provided")
	}

	return c.agent.Sign(key, data)
}

// SignWithFlags signs like Sign, but allows for additional flags to be sent/received
func (c *client) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	if key == nil {
		return nil, errors.New("null key provided")
	}

	return c.agent.SignWithFlags(key, data, flags)
}

// Add adds the given key to the agent.
func (c *client) Add(key agent.AddedKey) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.Add(key)
}

// Remove removes the key from the agent.
func (c *client) Remove(key ssh.PublicKey) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	if key == nil {
		return errors.New("null key provided")
	}

	return c.agent.Remove(key)
}

// RemoveAll removes all the keys from the agent.
func (c *client) RemoveAll() error {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.RemoveAll()
}

// Lock locks the agent.
func (c *client) Lock(passphrase []byte) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.Lock(passphrase)
}

// Unlock unlocks the agent.
func (c *client) Unlock(passphrase []byte) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.Unlock(passphrase)
}

// Signers returns the available singers the agent.
func (c *client) Signers() ([]ssh.Signer, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.Signers()
}

// Extension processes a custom extension request.
func (c *client) Extension(extensionType string, contents []byte) ([]byte, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	return c.agent.Extension(extensionType, contents)
}
