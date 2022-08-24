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

type agentLifetimeConstraint struct {
	LifetimeSecs uint32 `sshtype:"1"`
}

// Following messages define the operations to add/remove smartcard keys to/from the ssh agent.
const (
	// AgentMessageAddSmartcardKey is the SSH agent protocol numbers described in https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-01#rfc.section.7.1.
	// We use AgentMessageAddSmartcardKeyConstrained instead to add key lifetime constrains.
	AgentMessageAddSmartcardKey = 20
	// AgentMessageRemoveSmartcardKey is the SSH agent protocol numbers described in https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-01#rfc.section.7.1.
	AgentMessageRemoveSmartcardKey = 21
	// AgentMessageAddSmartcardKeyConstrained is the SSH agent protocol numbers described in https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-01#rfc.section.7.1.
	AgentMessageAddSmartcardKeyConstrained = 26

	// agentConstrainConfirm is the protocol number (sshtype) to identify whether the agent require explicit user confirmation for private key operation when using the key.
	// Ref: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-01#section-4.2.6.2
	agentConstrainConfirm = 2

	// agentFailure and agentSuccess is the response protocol number indicating whether the add-key operation is success or not.
	agentFailure = 5
	agentSuccess = 6
)

// agentAddSmartcardKeyReq defines the request to add a smartcard key.
// sshtype `26` is AgentMessageAddSmartcardKeyConstrained.
type agentAddSmartcardKeyReq struct {
	ID          string `sshtype:"26"`
	PIN         []byte
	Constraints []byte `ssh:"rest"`
}

// agentAddSmartcardKeyReq defines the request to remove a smartcard key.
// sshtype `21` is AgentMessageRemoveSmartcardKey.
type agentRemoveSmartcardKeyReq struct {
	ID  string `sshtype:"21"`
	PIN []byte
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
