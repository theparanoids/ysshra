// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package shimagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/theparanoids/ysshra/agent/ssh/connection"
	"github.com/theparanoids/ysshra/keyid"
	certutil "github.com/theparanoids/ysshra/sshutils/cert"
	keyutil "github.com/theparanoids/ysshra/sshutils/key"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	errAgentLocked      = errors.New("agent: locked")
	errAgentUnlocked    = errors.New("agent: not locked")
	errAgentNotFoundKey = errors.New("agent: key not found")
)

type certificate struct {
	*ssh.Certificate
	Blob    []byte
	Comment string
}

// Marshal marshals the blob of the certificate.
func (c *certificate) Marshal() []byte {
	return c.Blob
}

// signer is used to wrap a hardware certificate with
// corresponding ssh-agent.
type signer struct {
	cert  *certificate
	agent agent.Agent
}

// PublicKey returns the hardware certificate.
func (s signer) PublicKey() ssh.PublicKey { return s.cert }

// Sign signs the data by the hardware certificate key.
func (s signer) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.cert.Key, data)
}

type hashcode [sha256.Size]byte

func hash(data []byte) hashcode {
	return sha256.Sum256(data)
}

// Server is the shim agent service.
// It aims to "shim" the underlying ssh auth-agent with additional in-memory certificates.
// It provides some extra functionalities.
//  1. Automatically remove orphan certificates in memory.
//  2. Automatically remove expired certificates in memory and in the underlying agent.
//  3. Provide an option to not list upstream YSSHCA certificates. Note that it is still capable of
//     removing the certificates.
type Server struct {
	// mu protects the server's status and the connection with the underlying agent.
	mu sync.RWMutex

	// conn is the connection to the underlying ssh-agent.
	conn io.ReadWriteCloser
	// agent is the underlying ssh-agent created from Conn
	agent agent.Agent
	// certs stores the certificates with private key in hardware
	certs map[hashcode]*certificate

	// conds is used by Wait function to wait for a
	// specific message. Each index is corresponding
	// to a message code defined in message.go.
	conds [40]*sync.Cond

	// locked is prepared for Lock and Unlock functions,
	// when it is true, Sign and Remove will fail, and
	// List will return an empty list.
	locked bool

	// noUpstreamSSHCACert indicates the shimagent won't display the underlying agent's SSHCA
	// certificates with List and Signers operation.
	noUpstreamSSHCACert bool

	// upstreamSSHCACertCache is a map of fingerprint of upstream certificates.
	upstreamSSHCACertCache map[hashcode]struct{}

	// pubKeyComp is the compare function to compare ssh public keys.
	// The function is useful to list credentials in a specific order.
	pubKeyComp func(ssh.PublicKey, ssh.PublicKey) bool
}

// Option encapsulates the parameters of New function that create new ShimAgent objects.
type Option struct {
	// Address is used to connect to a YubiAgent Server.
	// The definition of address depends on OS.
	// For Darwin and Linux, address is a unix socket.
	// For Windows, address is a named pipe.
	Address string
	// NoUpstream indicates whether the server can access to the underlying agent through conn. If it
	// is set to true, an in-memory agent is created to handle the request.
	// The default value is false.
	NoUpstream bool
	// PubKeyComp is the compare function to compare ssh public keys.
	// The function is useful to list credentials in a specific order.
	// The default behavior is to compare the keys by their marshaled key value.
	PubKeyComp func(ssh.PublicKey, ssh.PublicKey) bool
}

// New will return a new ShimAgent object.
func New(opt Option) (ShimAgent, error) {
	conn, err := connection.GetConn(opt.Address)
	if err != nil {
		return nil, err
	}
	ag, err := newShimAgent(conn, opt.NoUpstream)

	if opt.PubKeyComp == nil {
		opt.PubKeyComp = func(x, y ssh.PublicKey) bool {
			return bytes.Equal(x.Marshal(), y.Marshal())
		}
	}
	ag.pubKeyComp = opt.PubKeyComp
	return ag, err
}

// newShimAgent returns a new ShimAgent object from an io.ReadWriteCloser.
// noUpstream indicates whether the server can access to the underlying agent through conn. If it
// is set to true, an in-memory agent is created to handle the request.
func newShimAgent(conn io.ReadWriteCloser, noUpstream bool) (*Server, error) {
	if conn == nil {
		return nil, errors.New("cannot start a shimagent with nil conn")
	}

	srv := &Server{
		conn:                   conn,
		agent:                  agent.NewClient(conn),
		certs:                  make(map[hashcode]*certificate),
		noUpstreamSSHCACert:    noUpstream,
		upstreamSSHCACertCache: make(map[hashcode]struct{}),
	}

	for i := range srv.conds {
		srv.conds[i] = sync.NewCond(&sync.Mutex{})
	}

	// Build cache to drop YSSHCA certs from upstream.
	if noUpstream {
		keys, err := srv.agent.List()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			if cert, err := keyutil.CastSSHPublicKeyToCertificate(key); err == nil {
				if _, err := keyid.Unmarshal(cert.KeyId); err == nil {
					// assumption is that we would not be able to parse certificates not generated by YSSHCA.
					// If additional checks are needed, like checking certain fields in keyid, those can be later added.
					srv.upstreamSSHCACertCache[hash(cert.Marshal())] = struct{}{}
				}
			}
		}
	}
	return srv, nil
}

// remove does the actual key removal. The caller must already be holding the mutex.
func (s *Server) remove(key ssh.PublicKey) error {
	removed := false

	// Remove the in-memory certificates.
	h := hash(key.Marshal())
	if _, ok := s.certs[h]; ok {
		delete(s.certs, h)
		removed = true
	}

	// Remove the in-agent key.
	err := s.agent.Remove(key)
	// If the public key is from the in-memory certificate, it returns a not found error from the
	// underlying agent.
	if err != nil && !removed {
		return err
	}

	if s.noUpstreamSSHCACert {
		// Remove the cert in the cache.
		// No need to check whether the hash in the map before delete().
		delete(s.upstreamSSHCACertCache, h)
	}

	return nil
}

// filter removes the invalid certs in the memory or in the underlying agent.
// 1. It removes the orphan certs in the memory. If the underlying agent returns an empty list, it
// might be locked by user. To support such case, we don't remove orphan certs.
// 2. It removes the expired certs in the memory and the underlying agent.
// The caller must hold the mutex before calling this method.
func (s *Server) filter() (inMemoryCerts map[hashcode]*certificate, inAgentKeys []*agent.Key, err error) {
	inMemoryCerts = s.certs
	inAgentKeys, err = s.agent.List()
	if err != nil {
		return nil, nil, err
	}

	remove := remover(func(pub ssh.PublicKey) error {
		if err := s.remove(pub); err != nil {
			return err
		}

		// Remove the in-agent key from the cached.
		for i, key := range inAgentKeys {
			if bytes.Equal(key.Marshal(), pub.Marshal()) {
				length := len(inAgentKeys)
				inAgentKeys[i] = inAgentKeys[length-1]
				inAgentKeys = inAgentKeys[:length-1]
				break
			}
		}
		return nil
	})

	if err := filterOrphanCerts(remove, inMemoryCerts, inAgentKeys); err != nil {
		return nil, nil, err
	}

	if err := filterExpiredCerts(remove, inMemoryCerts, inAgentKeys); err != nil {
		return nil, nil, err
	}

	return inMemoryCerts, inAgentKeys, nil
}

// Broadcast wakes all goroutines waiting on a specific operation.
// The value of msg is defined in message.go.
func (s *Server) Broadcast(msg byte) error {
	if msg < byte(len(s.conds)) {
		s.conds[msg].L.Lock()
		defer s.conds[msg].L.Unlock()

		s.conds[msg].Broadcast()
	}
	return nil
}

// Wait gets blocked until a specific operation is done.
// The value of msg is defined in message.go.
func (s *Server) Wait(msg byte) error {
	if msg < byte(len(s.conds)) {
		s.conds[msg].L.Lock()
		defer s.conds[msg].L.Unlock()

		s.conds[msg].Wait()
	}
	return nil
}

// Close closes the underlying `conn`.
// The underlying `agent` will be unreachable if it is created by the `conn`.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return errAgentLocked
	}

	return s.conn.Close()
}

// List returns the identities known to the agent.
func (s *Server) List() ([]*agent.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return []*agent.Key{}, nil
	}

	certsInMemory, keysInAgent, err := s.filter()
	if err != nil {
		return nil, err
	}

	var keys []*agent.Key
	for _, cert := range certsInMemory {
		keys = append(keys, marshalAgentKey(cert))
	}

	for _, key := range keysInAgent {
		cert, err := keyutil.CastSSHPublicKeyToCertificate(key)
		if err != nil {
			keys = append(keys, key)
			continue
		}

		keyHash := hash(cert.Marshal())
		if _, ok := s.upstreamSSHCACertCache[keyHash]; ok {
			continue
		}

		if _, err := keyid.Unmarshal(cert.KeyId); s.noUpstreamSSHCACert && err == nil {
			s.upstreamSSHCACertCache[keyHash] = struct{}{}
			continue
		}

		label, err := certutil.Label(cert)
		if err != nil {
			label = key.Comment
		} else if key.Comment != "" {
			label += "-" + key.Comment
		}

		keys = append(keys, marshalAgentKey(&certificate{cert, cert.Marshal(), label}))
	}

	sort.Slice(keys, func(i, j int) bool {
		return s.pubKeyComp(keys[i], keys[j])
	})

	return keys, err
}

// Forward forwards the unknown OpenSSH requests to the underlying ssh-agent.
func (s *Server) Forward(req []byte) (resp []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = write(s.conn, req); err != nil {
		return nil, err
	}
	return read(s.conn)
}

// AddHardCert adds a certificate with private key in the underlying agent.
// If key is not a certificate, it will be ignored.
func (s *Server) AddHardCert(key ssh.PublicKey, suffix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return errAgentLocked
	}

	if key == nil {
		return errors.New("null key provided")
	}

	keyHash := hash(key.Marshal())
	if _, ok := s.certs[keyHash]; ok {
		return nil
	}

	cert, err := keyutil.CastSSHPublicKeyToCertificate(key)
	if err != nil {
		return err
	}
	label, err := certutil.Label(cert)
	if err != nil {
		label = suffix
	} else if suffix != "" {
		label += "-" + suffix
	}

	agentKeys, err := s.agent.List()
	if err != nil {
		return err
	}
	for _, agentKey := range agentKeys {
		if bytes.Equal(agentKey.Marshal(), cert.Key.Marshal()) {
			s.certs[keyHash] = &certificate{cert, cert.Marshal(), label}
			return nil
		}
	}
	return errAgentNotFoundKey
}

func (s *Server) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return nil, errors.New("agent is locked")
	}

	if key == nil {
		return nil, errors.New("null key provided")
	}

	if _, _, err := s.filter(); err != nil {
		return nil, err
	}

	// There are two kinds of certificates, one is in-memory cert and the other is in-agent cert
	// If key is an in-memory certificate, its key is in the underlying agent, we need forward the
	// request to the underlying agent with the correct public key.
	// public key to tell ssh-agent which key it should use.
	if cert, err := keyutil.CastSSHPublicKeyToCertificate(key); err == nil {
		keyHash := hash(cert.Marshal())
		if _, ok := s.certs[keyHash]; ok {
			return s.agent.Sign(cert.Key, data)
		}
		if _, err := keyid.Unmarshal(cert.KeyId); err == nil && s.noUpstreamSSHCACert {
			// Only in-agent YSSHCA certs aren't available in no-upstream mode.
			return nil, errAgentNotFoundKey
		}
	}

	return s.agent.Sign(key, data)
}

// Add adds the given key to the agent.
func (s *Server) Add(key agent.AddedKey) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return errAgentLocked
	}

	return s.agent.Add(key)
}

// Remove removes the key from the agent.
func (s *Server) Remove(key ssh.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return errAgentLocked
	}

	if key == nil {
		return errors.New("null key provided")
	}

	return s.remove(key)
}

// RemoveAll removes all the keys from the agent.
func (s *Server) RemoveAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return errAgentLocked
	}

	s.certs = make(map[hashcode]*certificate)
	s.upstreamSSHCACertCache = make(map[hashcode]struct{})
	return s.agent.RemoveAll()
}

// Lock locks the shim agent.
// List, Sign, Add, Remove and operations of the agent will raise an errAgentLocked error.
func (s *Server) Lock(passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return errAgentLocked
	}

	err := s.agent.Lock(passphrase)
	if err == nil {
		s.locked = true
	}
	return err
}

// Unlock unlocks the shim agent.
func (s *Server) Unlock(passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.locked {
		return errAgentUnlocked
	}

	err := s.agent.Unlock(passphrase)
	if err == nil {
		s.locked = false
	}
	return err
}

// Signers returns the available singers from the in-memory certs and underlying agent.
func (s *Server) Signers() ([]ssh.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.locked {
		return nil, errors.New("agent is locked")
	}

	certsInMemory, keysInAgent, err := s.filter()
	if err != nil {
		return nil, err
	}

	signers := make([]ssh.Signer, 0, len(certsInMemory)+len(keysInAgent))
	for _, cert := range s.certs {
		signers = append(signers, signer{cert, s})
	}
	uss, err := s.agent.Signers()
	if err != nil {
		return nil, err
	}
	for _, signer := range uss {
		if !s.noUpstreamSSHCACert {
			signers = append(signers, signer)
			continue
		}

		cert, err := keyutil.CastSSHPublicKeyToCertificate(signer.PublicKey())
		if err != nil {
			signers = append(signers, signer)
			continue
		}

		keyHash := hash(cert.Marshal())
		if _, ok := s.upstreamSSHCACertCache[keyHash]; ok {
			continue
		}

		if _, err := keyid.Unmarshal(cert.KeyId); err == nil {
			s.upstreamSSHCACertCache[keyHash] = struct{}{}
			continue
		}
		signers = append(signers, signer)
	}

	sort.Slice(signers, func(i, j int) bool {
		return s.pubKeyComp(signers[i].PublicKey(), signers[j].PublicKey())
	})

	return signers, nil
}

// maxAgentResponseBytes is the maximum agent reply size that is accepted.
// This is a sanity check, not a limit in the spec.
const maxAgentResponseBytes = 16 << 20

func read(c io.Reader) (data []byte, err error) {
	var length [4]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return nil, err
	}

	l := binary.BigEndian.Uint32(length[:])
	if l > maxAgentResponseBytes {
		return nil, fmt.Errorf("data size too large: %d", l)
	}

	data = make([]byte, l)
	if _, err := io.ReadFull(c, data); err != nil {
		return nil, err
	}
	return data, nil
}

func write(c io.Writer, data []byte) (err error) {
	if len(data) > maxAgentResponseBytes {
		return fmt.Errorf("data size too large: %d", len(data))
	}

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	if _, err := c.Write(length[:]); err != nil {
		return err
	}
	if _, err := c.Write(data); err != nil {
		return err
	}
	return nil
}

func marshalAgentKey(key ssh.PublicKey) *agent.Key {
	ak := keyutil.CastSSHPublicKeyToAgentKey(key)
	if cert, ok := key.(*certificate); ok {
		ak.Comment = cert.Comment
	}
	return ak
}
