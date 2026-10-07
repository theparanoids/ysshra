// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// Agent protocol numbers and names from draft-miller-ssh-agent. They are not
// exported by golang.org/x/crypto/ssh/agent, whose client has no smartcard
// support at all.
const (
	msgFailure                    = 5
	msgSuccess                    = 6
	msgAddSmartcardKey            = 20
	msgRemoveSmartcardKey         = 21
	msgAddSmartcardKeyConstrained = 26

	constrainExtension = 255

	// extAssociatedCerts attaches certificates to the keys of a PKCS#11
	// provider as it is loaded. It was added in OpenSSH 9.6.
	extAssociatedCerts = "associated-certs-v00@openssh.com"

	// maxMessageBytes mirrors the sanity limit used by the agent packages.
	maxMessageBytes = 16 << 20
)

// ErrAgentFailure is returned when the agent answers SSH_AGENT_FAILURE.
var ErrAgentFailure = errors.New("yagent: agent refused the request")

// AddSmartcardKey loads the PKCS#11 provider into the agent and attaches certs
// to the provider keys they certify. Certificates whose public key matches no
// provider key are ignored by the agent. With no certs it sends a plain
// SSH_AGENTC_ADD_SMARTCARD_KEY, which every OpenSSH version understands.
//
// OpenSSH refuses to load a provider that is already loaded, so callers that
// change the certificate set must call RemoveSmartcardKey first.
func AddSmartcardKey(rw io.ReadWriter, provider string, pin []byte, certs []*ssh.Certificate) error {
	req := marshalAddSmartcardKey(provider, pin, certs)
	defer clear(req) // the request carries the PIN
	return expectSuccess(rw, req)
}

// RemoveSmartcardKey unloads the PKCS#11 provider and every identity backed by
// it, including the certificates attached to its keys.
func RemoveSmartcardKey(rw io.ReadWriter, provider string) error {
	var req []byte
	req = append(req, msgRemoveSmartcardKey)
	req = appendString(req, []byte(provider))
	req = appendString(req, nil) // PIN, unused by OpenSSH for removal
	return expectSuccess(rw, req)
}

func marshalAddSmartcardKey(provider string, pin []byte, certs []*ssh.Certificate) []byte {
	msg := byte(msgAddSmartcardKey)
	if len(certs) > 0 {
		msg = msgAddSmartcardKeyConstrained
	}
	req := []byte{msg}
	req = appendString(req, []byte(provider))
	req = appendString(req, pin)
	if len(certs) == 0 {
		return req
	}

	var blob []byte
	for _, cert := range certs {
		blob = appendString(blob, cert.Marshal())
	}
	req = append(req, constrainExtension)
	req = appendString(req, []byte(extAssociatedCerts))
	req = append(req, 0) // certs_only=false: keep the bare keys loaded too
	req = appendString(req, blob)
	return req
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func expectSuccess(rw io.ReadWriter, req []byte) error {
	resp, err := roundTrip(rw, req)
	if err != nil {
		return err
	}
	switch {
	case len(resp) == 0:
		return errors.New("yagent: empty agent response")
	case resp[0] == msgSuccess:
		return nil
	case resp[0] == msgFailure:
		return ErrAgentFailure
	default:
		return fmt.Errorf("yagent: unexpected agent response type %d", resp[0])
	}
}

func roundTrip(rw io.ReadWriter, req []byte) ([]byte, error) {
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(req)), uint32(len(req)))
	frame = append(frame, req...)
	defer clear(frame)
	if _, err := rw.Write(frame); err != nil {
		return nil, err
	}

	var length [4]byte
	if _, err := io.ReadFull(rw, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > maxMessageBytes {
		return nil, fmt.Errorf("yagent: agent response too large: %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
