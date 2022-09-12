// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//nolint:all
package yubiagent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theparanoids/ysshra/agent/utils"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type reset func()

func setConn(agent YubiAgent, conn net.Conn) reset {
	if c, ok := agent.(*client); ok {
		oldConn := c.conn
		c.conn = conn
		return func() { c.conn = oldConn }
	}
	return nil
}

// createSelfSignCert create a one-hour selfsigned certificate for unit tests
func createSelfSignCert(KeyID string) (*rsa.PrivateKey, *ssh.Certificate, error) {
	priv, pub, err := createPublicKey()
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	var cert = ssh.Certificate{
		Key:         pub,
		KeyId:       KeyID,
		ValidAfter:  uint64(time.Now().Unix()),
		ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err = cert.SignCert(rand.Reader, signer); err != nil {
		return nil, nil, err
	}
	return priv, &cert, nil
}

type mockAgentServer struct {
	YubiAgent
}

func (fs mockAgentServer) ListSlots() (slots []string, err error) {
	return []string{"9a", "9e"}, nil
}

func (fs mockAgentServer) ReadSlot(slot string) (cert *x509.Certificate, err error) {
	path := fmt.Sprintf("./testdata/Unittest_Authentication_%s.crt", slot)
	output, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return utils.ParsePEMCertificate(output)
}

func (fs mockAgentServer) AttestSlot(slot string) (cert *x509.Certificate, err error) {
	path := fmt.Sprintf("./testdata/Unittest_Authentication_%s_attest.crt", slot)
	output, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return utils.ParsePEMCertificate(output)
}

// createClient create a fake client for unit tests.
func createClient(s YubiAgent) (c YubiAgent, cleanup func()) {
	c1, c2 := net.Pipe()
	go ServeAgent(s, c1)
	return &client{c2, sync.Mutex{}, sshagent.NewClient(c2)}, func() {
		c1.Close()
		c2.Close()
	}
}

func TestClientAddHardCert(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	err := agent.AddHardCert(nil, "")
	if err == nil || err.Error() != "null key provided" {
		t.Errorf("unexpected error: %v", err)
	}

	_, key, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	err = agent.AddHardCert(key, "")
	if err == nil || err.Error() != "the key type is not cert" {
		t.Errorf("unexpected error: %v", err)
	}

	priv, cert, err := createSelfSignCert(`{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{
		PrivateKey: priv,
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = agent.AddHardCert(cert, "") // without comment
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ := agent.List()
	if len(keys) != 2 {
		t.Fatalf("expect %v certificates, got %v", 2, len(keys))
	}
	if !bytes.Equal(keys[0].Marshal(), cert.Marshal()) {
		t.Errorf("expect %v, got %v", cert, keys[0])
	}
	if keys[0].Comment != "TouchSudoSSH-a7af667d" {
		t.Errorf("expect comment %v, got %v", "TouchSudoSSH-a7af667d", keys[0].Comment)
	}
	if err := agent.RemoveAll(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	priv, cert, err = createSelfSignCert(`{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{
		PrivateKey: priv,
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = agent.AddHardCert(cert, "9a") // with comment
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ = agent.List()
	if len(keys) != 2 {
		t.Fatalf("expect %v certificates, got %v", 2, len(keys))
	}
	if keys[0].Comment != "TouchSudoSSH-a7af667d-9a" {
		t.Errorf("expect comment %v, got %v", "TouchSudoSSH-a7af667d-9a", keys[0].Comment)
	}
	if err := agent.RemoveAll(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	priv, cert, err = createSelfSignCert(`{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":1,"ver":1}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{
		PrivateKey: priv,
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = agent.AddHardCert(cert, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should find 1 priv key and 1 cert.
	keys, _ = agent.List()
	if len(keys) != 2 {
		t.Fatalf("expect %v certificates, got %v", 2, len(keys))
	}
	// Make sure keys[0] is the cert.
	if !strings.Contains(keys[0].Type(), "cert") {
		keys[0], keys[1] = keys[1], keys[0]
	}
	for _, key := range keys {
		if !bytes.Equal(key.Marshal(), cert.Marshal()) {
			continue
		}
		if key.Comment != "TouchlessSSH-a7af667d" {
			t.Errorf("expect comment %v, got %v", "TouchlessSSH-a7af667d", key.Comment)
		}
	}
}

func TestClientListSlots(t *testing.T) {
	c, cleanup := createClient(mockAgentServer{})
	defer cleanup()

	slots, err := c.ListSlots()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(slots, []string{"9a", "9e"}) {
		t.Errorf("expect %v, got %v", []string{"9a", "9e"}, slots)
	}
}

func TestClientReadSlot(t *testing.T) {
	c, cleanup := createClient(mockAgentServer{})
	defer cleanup()

	slots := []string{"9a", "9e"}
	for _, slot := range slots {
		cert, err := c.ReadSlot(slot)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		path := fmt.Sprintf("./testdata/Unittest_Authentication_%s.crt", slot)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expect, err := utils.ParsePEMCertificate(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(cert.Raw, expect.Raw) {
			t.Errorf("expect %v, got %v", expect, cert)
		}
	}
}

func TestClientAttestSlot(t *testing.T) {
	c, cleanup := createClient(mockAgentServer{})
	defer cleanup()

	slots := []string{"9a", "9e"}
	for _, slot := range slots {
		cert, err := c.AttestSlot(slot)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		path := fmt.Sprintf("./testdata/Unittest_Authentication_%s_attest.crt", slot)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expect, err := utils.ParsePEMCertificate(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(cert.Raw, expect.Raw) {
			t.Errorf("expect %v, got %v", expect, cert)
		}
	}
}

func TestWait(t *testing.T) {
	s := testServer(t)
	c1, cleanup1 := createClient(s)
	defer cleanup1()
	c2, cleanup2 := createClient(s)
	defer cleanup2()

	start := time.Now()
	go func() {
		time.Sleep(500 * time.Millisecond)
		c1.List()
	}()
	c2.Wait(AgentMessageRequestIdentities)
	if time.Since(start) < 500*time.Millisecond {
		t.Errorf("wait didn't block")
	}
}

func TestClientClose(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	conn := &mockConn{}
	setConn(agent, conn)

	agent.Close()
	if !conn.closeFlag {
		t.Error("failed to close connection")
	}
}

func TestClientForward(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	reset := setConn(agent, &mockConn{buffer: new(bytes.Buffer)})
	defer reset()

	resp, err := agent.Forward([]byte("unit-test"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !bytes.Equal(resp, []byte("unit-test")) {
		t.Errorf("expect %v, got %v", "unit-test", string(resp))
	}

	reset = setConn(agent, mockConnNowr{})
	defer reset()
	_, err = agent.Forward([]byte("unit-test"))
	if err == nil || err.Error() != "write error" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientList(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	// Add regular certificate.
	priv, regularCert, err := createSelfSignCert(`{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{
		PrivateKey: priv,
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := agent.AddHardCert(regularCert, "comment"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, err := agent.List()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should find 1 priv key and 1 cert.
	if len(keys) != 2 {
		t.Fatalf("expect %v keys, got: %v", 2, len(keys))
	}
	// Make sure keys[0] is the cert.
	if !strings.Contains(keys[0].Type(), "cert") {
		keys[0], keys[1] = keys[1], keys[0]
	}
	if !bytes.Equal(keys[0].Marshal(), regularCert.Marshal()) {
		t.Errorf("expect certificate %v, got %v", string(ssh.MarshalAuthorizedKey(regularCert)), keys[1])
	}

	// Add expired certificate
	_, expiredCert, err := createSelfSignCert(`{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`)
	if err != nil {
		t.Fatal(err)
	}
	expiredCert.ValidBefore = uint64(time.Now().Add(-2 * time.Hour).Unix())
	agent.AddHardCert(expiredCert, "comment")
	keys, err = agent.List()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expect %v key, got: %v", 2, len(keys))
	}
}

func TestClientSign(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	_, err := agent.Sign(nil, nil)
	if err == nil || err.Error() != "null key provided" {
		t.Errorf("unexpected error: %v", err)
	}

	// Add a static key
	priv, pub, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	sig, err := agent.Sign(pub, []byte("unit-test"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err = pub.Verify([]byte("unit-test"), sig); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Add a self-signed certificate
	priv, cert, err := createSelfSignCert("")
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := agent.AddHardCert(cert, "comment"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	sig, err = agent.Sign(cert, []byte("unit-test"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err = cert.Key.Verify([]byte("unit-test"), sig); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientAdd(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	priv, pub, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	err = agent.Add(sshagent.AddedKey{PrivateKey: priv})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ := agent.List()
	if !bytes.Equal(keys[0].Marshal(), pub.Marshal()) {
		t.Errorf("failed to add new key")
	}
}

func TestClientRemove(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	err := agent.Remove(nil)
	if err == nil || err.Error() != "null key provided" {
		t.Errorf("unexpected error: %v", err)
	}

	priv, pub, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ := agent.List()
	if len(keys) != 1 {
		t.Fatalf("expect %v keys, got %v", 1, len(keys))
	}

	if err = agent.Remove(pub); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ = agent.List()
	if len(keys) != 0 {
		t.Fatalf("expect %v keys, got %v", 0, len(keys))
	}

	priv, cert, err := createSelfSignCert(`{"prins":[],"transID":"a7af667d","reqUser":"","reqIP":"","reqHost":"","isFirefighter":false,"isHWKey":true,"isHeadless":false,"isNonce":false,"touchPolicy":3,"ver":1}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{
		PrivateKey: priv,
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := agent.AddHardCert(cert, "comment"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ = agent.List()
	if len(keys) != 2 {
		t.Fatalf("expect %v keys, got %v", 2, len(keys))
	}

	if err = agent.Remove(cert); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ = agent.List()
	if len(keys) != 1 {
		t.Fatalf("expect %v keys, got %v", 1, len(keys))
	}
}

func TestClientRemoveAll(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	priv, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ := agent.List()
	if len(keys) != 1 {
		t.Fatalf("expect %v keys, got %v", 1, len(keys))
	}

	if err := agent.RemoveAll(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ = agent.List()
	if len(keys) != 0 {
		t.Fatalf("expect %v keys, got %v", 0, len(keys))
	}
}

func TestClientLock(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := agent.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ := agent.List()
	if len(keys) != 1 {
		t.Fatalf("expect %v keys, got %v", 1, len(keys))
	}

	if err := agent.Lock([]byte("123456")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	keys, _ = agent.List()
	if len(keys) != 0 {
		t.Fatalf("expect %v keys, got %v", 0, len(keys))
	}
}

func TestClientUnlock(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	priv, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if keys, _ := agent.List(); len(keys) != 1 {
		t.Fatalf("expect %v keys, got %v", 1, len(keys))
	}
	if err = agent.Lock([]byte("123456")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if keys, _ := agent.List(); len(keys) != 0 {
		t.Fatalf("expect %v keys, got %v", 0, len(keys))
	}

	// Try wrong passphrase
	err = agent.Unlock([]byte("654321"))
	// NOTE: server side returns "incorrect passphrase", client side just returns "failure"
	if err == nil || !(strings.Contains(err.Error(), "incorrect passphrase") || strings.Contains(err.Error(), "failure")) {
		t.Errorf("unexpected error: %v", err)
	}
	if keys, _ := agent.List(); len(keys) != 0 {
		t.Fatalf("expect %v keys, got %v", 0, len(keys))
	}

	// Try correct passphrase
	if err := agent.Unlock([]byte("123456")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if keys, _ := agent.List(); len(keys) != 1 {
		t.Fatalf("expect %v keys, got %v", 1, len(keys))
	}
}

func TestClientSigners(t *testing.T) {
	agent, cleanup := createClient(testServer(t))
	defer cleanup()

	priv, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	signers, err := agent.Signers()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expect %v signers, got %v", 1, len(signers))
	}
}

func TestClientAddSmartcardKey(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// generate expected with
		// - nc -Ul sock </dev/null | xxd -i -c 1
		// - env SSH_AUTH_SOCK=sock ssh-add -s /path/to/lib -t 5
		// (use passhprase '123')
		expected := []byte{
			0x00, 0x00, 0x00, 0x1d, 0x1a, 0x00, 0x00, 0x00, 0x0c, 0x2f, 0x70, 0x61,
			0x74, 0x68, 0x2f, 0x74, 0x6f, 0x2f, 0x6c, 0x69, 0x62, 0x00, 0x00, 0x00,
			0x03, 0x31, 0x32, 0x33, 0x01, 0x00, 0x00, 0x00, 0x05,
		}

		got := make([]byte, len(expected))
		_, err := io.ReadFull(c1, got)
		if err != nil {
			t.Errorf("unexpected error from Read: %v", err)
		}

		_, _ = c1.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x06})

		if !bytes.Equal(expected, got) {
			t.Errorf("bad request from AddSmartcardKey; expected %v got %v", expected, got)
		}
	}()

	c := &client{c2, sync.Mutex{}, sshagent.NewClient(c2)}
	err := c.AddSmartcardKey("/path/to/lib", []byte("123"), 5*time.Second, false)
	if err != nil {
		t.Fatal("unexpected error from AddSmartcardKey: ", err)
	}

	wg.Wait()

	c1.Close()

	err = c.AddSmartcardKey("/path/to/lib", []byte("123"), 5*time.Second, false)
	if err == nil {
		t.Fatal("didn't get error from AddSmartcardKey with closed connection")
	}
}

func TestClientRemoveSmartcardKey(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// generate expected with
		// - nc -Ul sock </dev/null | xxd -i -c 1
		// - env SSH_AUTH_SOCK=sock ssh-add -e /path/to/lib
		expected := []byte{
			0x00, 0x00, 0x00, 0x15, 0x15, 0x00, 0x00, 0x00, 0x0c, 0x2f, 0x70, 0x61,
			0x74, 0x68, 0x2f, 0x74, 0x6f, 0x2f, 0x6c, 0x69, 0x62, 0x00, 0x00, 0x00,
			0x00,
		}

		got := make([]byte, len(expected))
		_, err := io.ReadFull(c1, got)
		if err != nil {
			t.Errorf("unexpected error from Read: %v", err)
		}

		_, _ = c1.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x06})

		if !bytes.Equal(expected, got) {
			t.Errorf("bad request from RemoveSmartcardKey; expected %v got %v", expected, got)
		}
	}()

	c := &client{c2, sync.Mutex{}, sshagent.NewClient(c2)}
	err := c.RemoveSmartcardKey("/path/to/lib", nil)
	if err != nil {
		t.Fatal("unexpected error from RemoveSmartcardKey: ", err)
	}

	wg.Wait()

	c1.Close()

	err = c.RemoveSmartcardKey("/path/to/lib", nil)
	if err == nil {
		t.Fatal("didn't get error from RemoveSmartcardKey with closed connection")
	}
}
