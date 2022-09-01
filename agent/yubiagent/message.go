// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

// message.go contains the constants and the message structures which are used in communication.

import (
	"bytes"
	"io"

	"github.com/rs/zerolog/log"
)

// Following messages are the ssh agent protocol number, which are used as the tags of sshtype in a yubiagent request.
// These numbers extend the SSH agent protocol.
const (
	// AgentMessageAddHardCert extends the SSH agent protocol numbers for the YubiKey's capability
	// to add hardware certificate.
	AgentMessageAddHardCert = 31
	// AgentMessageListSlots extends the SSH agent protocol numbers for the YubiKey's capability to
	// list keys in slots.
	AgentMessageListSlots = 32
	// AgentMessageReadSlot extends the SSH agent protocol numbers for the YubiKey's capability to
	// read key in the slot.
	AgentMessageReadSlot = 33
	// AgentMessageAttestSlot extends the SSH agent protocol numbers for the YubiKey's capability to
	// attest the key in slot.
	AgentMessageAttestSlot = 34
	// AgentMessageWait extends the SSH agent protocol numbers for the YubiKey's capability to wait
	// for the specified operation finished.
	AgentMessageWait = 35
)

// agentAddHardCertReq defines the request to add hard certs.
// sshtype `31` is AgentMessageAddHardCert.
type agentAddHardCertReq struct {
	KeyBlob []byte `sshtype:"31"`
	Comment string
}

type agentListSlotsResp struct {
	Slots []string
	Err   string
}

type agentReadSlotResp struct {
	Cert []byte
	Err  string
}

type agentAttestSlotResp struct {
	Cert []byte
	Err  string
}

// A request with any following ssh agent protocol numbers require a forwarder (see: struct forwarder)
// to forward net.Conn from YSSHRA, yubiagent to SSH agent.
// See [PROTOCOL.agent], section 3: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-00
const (
	// AgentMessageRequestV1Identities helps backward compatibility for the request keys.
	AgentMessageRequestV1Identities = 1

	// 3.2 Requests from client to agent for protocol 2 key operations
	// The protocol numbers are described in https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-01#rfc.section.7.1.

	// AgentMessageRequestIdentities is the SSH agent protocol number for agent.List.
	AgentMessageRequestIdentities = 11
	// AgentMessageSignRequest is the SSH agent protocol number for agent.Sign.
	AgentMessageSignRequest = 13
	// AgentMessageAddIdentity is the SSH agent protocol number for agent.Add.
	AgentMessageAddIdentity = 17
	// AgentMessageRemoveIdentity is the SSH agent protocol number for agent.Remove.
	AgentMessageRemoveIdentity = 18
	// AgentMessageRemoveAllIdentities is the SSH agent protocol number for agent.RemoveAll.
	AgentMessageRemoveAllIdentities = 19
	// AgentMessageAddIDConstrained is the SSH agent protocol number for agent.Add.
	AgentMessageAddIDConstrained = 25

	// 3.3 Key-type independent requests from client to agent.

	// AgentMessageLock is the SSH agent protocol number for agent.Lock.
	AgentMessageLock = 22
	// AgentMessageUnlock is the SSH agent protocol number for agent.Unlock.
	AgentMessageUnlock = 23
)

type forwarder struct {
	in  io.Reader
	out io.Writer
}

func newForwarder(req []byte, resp io.Writer) forwarder {
	buffer := new(bytes.Buffer)
	if err := write(buffer, req); err != nil {
		log.Warn().Err(err).Msg("failed to create forwarder when writing the buffer to resp")
	}
	return forwarder{in: buffer, out: resp}
}

// Read reads up to len(p) bytes from forwarder's buffer into p.
func (f forwarder) Read(p []byte) (n int, err error) {
	return f.in.Read(p)
}

// Write writes len(p) bytes from p to the out data stream.
func (f forwarder) Write(p []byte) (n int, err error) {
	return f.out.Write(p)
}
