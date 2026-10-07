// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"fmt"
	"os"
	"time"

	"github.com/theparanoids/ysshra/agent/ssh/connection"
	"golang.org/x/crypto/ssh"
)

// PINSource supplies the PKCS#11 PIN at the moment it is needed. yagent never
// keeps a PIN: the returned slice is zeroed right after the request is sent.
type PINSource interface {
	PIN() ([]byte, error)
}

// PINFunc adapts a function to a PINSource.
type PINFunc func() ([]byte, error)

// PIN implements PINSource.
func (f PINFunc) PIN() ([]byte, error) { return f() }

// EnvPIN reads the PIN from the named environment variable. It exists for
// tests and demos only; production deployments should read the PIN from the
// OS credential store at the time of use.
type EnvPIN string

// PIN implements PINSource.
func (e EnvPIN) PIN() ([]byte, error) {
	pin, ok := os.LookupEnv(string(e))
	if !ok {
		return nil, fmt.Errorf("yagent: %s is not set", string(e))
	}
	return []byte(pin), nil
}

// Plugger (re)loads a PKCS#11 provider into the agent with every valid stored
// certificate attached.
type Plugger struct {
	// Socket is the inner ssh-agent socket.
	Socket string
	// Provider is the path of the PKCS#11 module.
	Provider string
	PIN      PINSource
	Store    *CertStore
	// Now defaults to time.Now.
	Now func() time.Time
}

// Plug replaces the provider's identities in the agent: it unloads the
// provider, then loads it again with the currently valid certificates. OpenSSH
// cannot attach certificates to an already-loaded provider, so this is the only
// way to change the attached set.
//
// Every call costs exactly one PIN verification. Callers that run
// automatically (for example after each agent respawn) must bound how often
// they call it, or a wrong PIN can lock the token.
func (p *Plugger) Plug() (attached []*ssh.Certificate, err error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	stored, loadErr := p.Store.Valid(now())
	for _, sc := range stored {
		attached = append(attached, sc.Cert)
	}

	conn, err := connection.GetConn(p.Socket)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// The provider may simply not be loaded yet; a failure here is expected.
	_ = RemoveSmartcardKey(conn, p.Provider)

	pin, err := p.PIN.PIN()
	if err != nil {
		return nil, err
	}
	defer clear(pin)
	if err := AddSmartcardKey(conn, p.Provider, pin, attached); err != nil {
		return nil, fmt.Errorf("load PKCS#11 provider %s with %d cert(s): %w", p.Provider, len(attached), err)
	}
	// A provider that loaded fine is a success even if some backup files
	// were unreadable; surface those as a non-fatal error.
	return attached, loadErr
}
