// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//go:build e2e && !windows

package yagent

// End-to-end test against a real PKCS#11 token and a stock OpenSSH ssh-agent.
// Run it with agent/yagent/e2e/run.sh, which sets up SoftHSM in a container.
//
//	YAGENT_E2E_PKCS11  path of the PKCS#11 module holding one EC key
//	YAGENT_E2E_PIN     user PIN of the token
//	YAGENT_E2E_AGENT   ssh-agent binary (default: ssh-agent in PATH)

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/theparanoids/ysshra/agent/ssh/connection"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestE2EPKCS11CertsLiveInStockAgent(t *testing.T) {
	module := os.Getenv("YAGENT_E2E_PKCS11")
	if module == "" || os.Getenv("YAGENT_E2E_PIN") == "" {
		t.Skip("YAGENT_E2E_PKCS11 and YAGENT_E2E_PIN are required")
	}
	agentPath := os.Getenv("YAGENT_E2E_AGENT")
	if agentPath == "" {
		agentPath = sshAgentPath(t)
	}
	module, err := filepath.EvalSymlinks(module)
	if err != nil {
		t.Fatal(err)
	}

	dir := shortSocketDir(t)
	sock := SocketPath(dir)
	store := &CertStore{Dir: CertDir(dir)}
	d := NewDaemon(Config{
		Dir:           dir,
		AgentPath:     agentPath,
		AgentArgs:     []string{"-P", module},
		Provider:      module,
		PIN:           EnvPIN("YAGENT_E2E_PIN"),
		SweepInterval: 200 * time.Millisecond,
		Logf:          t.Logf,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := d.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	// 1. A fresh agent gets the bare PKCS#11 key, with no certificate yet.
	var hwKey ssh.PublicKey
	waitFor(t, "PKCS#11 key in agent", func() bool {
		ids := listIdentities(t, sock)
		if len(ids.plain) == 1 {
			hwKey = ids.plain[0]
			return true
		}
		return false
	})
	t.Logf("hardware key: %s", ssh.FingerprintSHA256(hwKey))

	// 2. Attach a certificate. The agent itself now holds it: List shows it
	// and it signs with the hardware key, with no shim in the path.
	longCert := newTestCert(t, hwKey, "long-lived", time.Now().Add(time.Hour))
	if err := store.Put(longCert, ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Replug(); err != nil {
		t.Fatal(err)
	}
	assertCerts(t, sock, "long-lived")
	assertSigns(t, sock, longCert)

	// 3. Add a second, short-lived certificate later. OpenSSH cannot extend a
	// loaded provider, so this exercises the unload/reload path.
	shortCert := newTestCert(t, hwKey, "short-lived", time.Now().Add(8*time.Second))
	if err := store.Put(shortCert, ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Replug(); err != nil {
		t.Fatal(err)
	}
	assertCerts(t, sock, "long-lived", "short-lived")
	assertSigns(t, sock, shortCert)
	for i, k := range listIdentities(t, sock).all {
		t.Logf("identity %d: %s %s", i, k.Type(), k.Comment)
	}

	// 4. Crash the agent. The replacement is restored from disk: yagent
	// had nothing in memory to replay.
	pid := d.Supervisor().Pid()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "agent restart", func() bool {
		p := d.Supervisor().Pid()
		return p != 0 && p != pid && len(listIdentities(t, sock).certs) == 2
	})
	assertCerts(t, sock, "long-lived", "short-lived")
	assertSigns(t, sock, longCert)

	// 5. The short-lived certificate is swept from the agent and the store
	// once it expires.
	waitFor(t, "expired cert swept", func() bool {
		return len(listIdentities(t, sock).certs) == 1
	})
	assertCerts(t, sock, "long-lived")
	if stored, _ := store.Load(); len(stored) != 1 || stored[0].Cert.KeyId != "long-lived" {
		t.Fatalf("store holds %d certs, want only long-lived", len(stored))
	}
}

type identities struct {
	all   []*agent.Key
	plain []ssh.PublicKey
	certs []*ssh.Certificate
}

// listIdentities returns what the agent holds, or nothing while the agent is
// restarting, so callers can poll it.
func listIdentities(t *testing.T, sock string) identities {
	t.Helper()
	conn, err := connection.GetConn(sock)
	if err != nil {
		return identities{}
	}
	defer func() { _ = conn.Close() }()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return identities{}
	}
	ids := identities{all: keys}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			t.Fatal(err)
		}
		if c, ok := pub.(*ssh.Certificate); ok {
			ids.certs = append(ids.certs, c)
		} else {
			ids.plain = append(ids.plain, pub)
		}
	}
	return ids
}

func assertCerts(t *testing.T, sock string, keyIDs ...string) {
	t.Helper()
	ids := listIdentities(t, sock)
	got := map[string]bool{}
	for _, c := range ids.certs {
		got[c.KeyId] = true
	}
	if len(ids.certs) != len(keyIDs) {
		t.Fatalf("agent holds %d certs, want %v", len(ids.certs), keyIDs)
	}
	for _, id := range keyIDs {
		if !got[id] {
			t.Fatalf("agent is missing cert %q", id)
		}
	}
	if len(ids.plain) != 1 {
		t.Fatalf("agent holds %d plain keys, want the 1 hardware key", len(ids.plain))
	}
}

// assertSigns asks the agent to sign with the certificate identity and checks
// the signature against the certified hardware key.
func assertSigns(t *testing.T, sock string, cert *ssh.Certificate) {
	t.Helper()
	conn, err := connection.GetConn(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	sig, err := agent.NewClient(conn).Sign(cert, data)
	if err != nil {
		t.Fatalf("sign with cert %q: %v", cert.KeyId, err)
	}
	if err := cert.Key.Verify(data, sig); err != nil {
		t.Fatalf("signature from cert %q does not verify: %v", cert.KeyId, err)
	}
}
