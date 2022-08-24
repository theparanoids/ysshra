// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/theparanoids/ysshra/agent/utils"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/theparanoids/ysshra/agent/shimagent"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type server struct {
	shimagent.ShimAgent
	pivtoolpath string
	remote      bool // In remote mode, yubiAgent will behave as a shimAgent.
}

// NewServer will create a new server that implements yubiagent.YubiAgent interface.
// The parameter address is used to connect to a real ssh-agent.
// The definition of address depends on OS.
// For Darwin and Linux, address is a unix socket.
// For Windows, address is a named pipe.
func NewServer(address string, remote bool) (YubiAgent, error) {
	var srv *server
	shimAgent, err := shimagent.New(
		shimagent.Option{
			Address:    address,
			NoUpstream: false,
		})
	if err != nil {
		return nil, err
	}

	var path string
	if !remote {
		path, err = getPivToolPath()
		if err != nil {
			return nil, err
		}
	}
	srv = &server{
		shimAgent,
		path,
		remote,
	}
	return srv, nil
}

// ListSlots lists all the used slots in YubiKey.
func (s *server) ListSlots() (slots []string, err error) {
	if s.remote {
		return nil, errors.New("yubiagent: ListSlots is not supported in remote mode")
	}
	output, err := exec.Command(s.pivtoolpath, "-a", "status").Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(output), "\n") {
		// Expect to find a line like "Slot 9a:"
		if len(line) >= 6 && line[:4] == "Slot" {
			slots = append(slots, line[5:7])
		}
	}
	return slots, nil
}

// ReadSlot reads x509 certificate in PEM format from the specified slot.
func (s *server) ReadSlot(slot string) (cert *x509.Certificate, err error) {
	if s.remote {
		return nil, errors.New("yubiagent: ReadSlot is not supported in remote mode")
	}
	output, err := exec.Command(s.pivtoolpath, "-a", "read-certificate", "-s", slot).Output()
	if err != nil {
		return nil, err
	}
	return utils.ParsePEMCertificate(output)
}

// AttestSlot signs the public key of the specified slot with the private key of "f9" slot and
// returns the resulting attestation certificate in PEM format, which can be verified later on.
func (s *server) AttestSlot(slot string) (cert *x509.Certificate, err error) {
	if s.remote {
		return nil, errors.New("yubiagent: AttestSlot is not supported in remote mode")
	}
	output, err := exec.Command(s.pivtoolpath, "-a", "attest", "-s", slot).Output()
	if err != nil {
		return nil, err
	}
	return utils.ParsePEMCertificate(output)
}

// AddSmartcardKey adds the specified smartcard to the agent.
// The request should be forwarded (see: ServeAgent), and be handled by the wrapped SSH agent server.
func (_ *server) AddSmartcardKey(readerId string, pin []byte, lifetime time.Duration, confirmBeforeUse bool) error {
	return errors.New("yubiagent: AddSmartcardKey is not implemented in server")
}

// RemoveSmartcardKey removes the specified smartcard from the agent.
// The request should be forwarded (see: ServeAgent), and be handled by the wrapped SSH agent server.
func (_ *server) RemoveSmartcardKey(readerId string, pin []byte) error {
	return errors.New("yubiagent: RemoveSmartcardKey in not implemented in server")
}

// ServeAgent uses an agent (usually a server object) to serve the connection c.
func ServeAgent(agent YubiAgent, c io.ReadWriter) error {
	for {
		req, err := read(c)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if yubiServer, ok := agent.(*server); ok {
			if shimServer, ok := yubiServer.ShimAgent.(*shimagent.Server); ok {
				if err := shimServer.Broadcast(req[0]); err != nil {
					return err
				}
			}
		}

		switch req[0] {
		case AgentMessageAddHardCert:
			var key ssh.PublicKey
			var comment string
			// To be compatible with old AddHardCert format
			if key, err = ssh.ParsePublicKey(req[1:]); err != nil {
				var msg agentAddHardCertReq
				if err = ssh.Unmarshal(req, &msg); err != nil {
					return err
				}
				if key, err = ssh.ParsePublicKey(msg.KeyBlob); err != nil {
					return err
				}
				comment = msg.Comment
			}

			var writeErr error
			if err = agent.AddHardCert(key, comment); err != nil {
				writeErr = write(c, []byte(err.Error()))
			} else {
				writeErr = write(c, []byte("SUCCESS"))
			}
			if writeErr != nil {
				log.Warn().Err(writeErr).Msg("failed to write response to the connection")
			}

		case AgentMessageListSlots:
			var msg agentListSlotsResp
			msg.Slots, err = agent.ListSlots()
			if err != nil {
				msg.Err = err.Error()
			}
			if err = write(c, ssh.Marshal(&msg)); err != nil {
				return err
			}

		case AgentMessageReadSlot:
			var msg agentReadSlotResp
			var cert *x509.Certificate
			cert, err = agent.ReadSlot(string(req)[1:])
			if cert != nil {
				block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
				msg.Cert = pem.EncodeToMemory(block)
			}
			if err != nil {
				msg.Err = err.Error()
			}
			if err = write(c, ssh.Marshal(&msg)); err != nil {
				return err
			}

		case AgentMessageAttestSlot:
			var msg agentAttestSlotResp
			var cert *x509.Certificate
			cert, err = agent.AttestSlot(string(req)[1:])
			if cert != nil {
				block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
				msg.Cert = pem.EncodeToMemory(block)
			}
			if err != nil {
				msg.Err = err.Error()
			}
			if err = write(c, ssh.Marshal(&msg)); err != nil {
				return err
			}

		case AgentMessageWait:
			var writeErr error
			if err = agent.Wait(req[1]); err != nil {
				writeErr = write(c, []byte(err.Error()))
			} else {
				writeErr = write(c, []byte("SUCCESS"))
			}
			if writeErr != nil {
				log.Warn().Err(writeErr).Msg("failed to write response to the connection")
			}

		case
			AgentMessageLock, AgentMessageUnlock, AgentMessageSignRequest,
			AgentMessageAddIdentity, AgentMessageAddIDConstrained,
			AgentMessageRemoveIdentity, AgentMessageRemoveAllIdentities,
			AgentMessageRequestV1Identities, AgentMessageRequestIdentities:

			forwarder := newForwarder(req, c)
			err = sshagent.ServeAgent(agent, forwarder)
			if err != nil && err != io.EOF {
				return err
			}

		default:
			// crypto/ssh/agent library doesn't understand some of
			// OpenSSH requests, so we forward the raw request.
			resp, err := agent.Forward(req)
			if err != nil {
				return err
			}
			if err := write(c, resp); err != nil {
				return err
			}
		}
	}
}
