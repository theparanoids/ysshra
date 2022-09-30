// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package shimagent

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ShimAgent is an interface that extends the functionality
// of the Agent interface in golang.org/x/crypto/ssh/agent.
type ShimAgent interface {
	agent.ExtendedAgent

	// Forward is prepared for unknown OpenSSH request,
	// it will simply forward the request to the ssh-agent.
	Forward(req []byte) (resp []byte, err error)

	// AddHardCert adds a certificate with private key in hardware.
	// If key is not a certificate, it will be ignored.
	AddHardCert(key ssh.PublicKey, comment string) error

	// Wait gets blocked until a specific operation is done.
	// The value of agentMsg is defined in message.go.
	Wait(agentMsg byte) error

	// Close closes all the created connections.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error
}
