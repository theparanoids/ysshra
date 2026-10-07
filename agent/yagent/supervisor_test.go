// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//go:build !windows

package yagent

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/theparanoids/ysshra/agent/ssh/connection"
	"golang.org/x/crypto/ssh/agent"
)

// shortSocketDir returns a directory short enough for a unix socket path;
// t.TempDir() on macOS can exceed the 104-byte sun_path limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "yagent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func sshAgentPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent not found in PATH")
	}
	return path
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSupervisorRestartsAndRestores(t *testing.T) {
	sock := filepath.Join(shortSocketDir(t), "agent.sock")
	priv, _ := newTestKey(t)

	var starts atomic.Int32
	s := &Supervisor{
		AgentPath:    sshAgentPath(t),
		Socket:       sock,
		RestartDelay: 10 * time.Millisecond,
		Logf:         t.Logf,
		// Stand-in for restoring certificates: prove the hook runs against
		// every new agent by loading a key into it.
		OnStart: func(context.Context) error {
			starts.Add(1)
			conn, err := connection.GetConn(sock)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			return agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: priv})
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, "first start", func() bool { return starts.Load() == 1 })
	firstPid := s.Pid()
	if n := countKeys(t, sock); n != 1 {
		t.Fatalf("agent has %d keys after start, want 1", n)
	}

	// SIGKILL leaves the socket file behind, like a real crash.
	if err := syscall.Kill(firstPid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restart", func() bool { return starts.Load() == 2 && s.Pid() != 0 && s.Pid() != firstPid })
	if n := countKeys(t, sock); n != 1 {
		t.Fatalf("agent has %d keys after restart, want 1", n)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil after cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after graceful stop: %v", err)
	}
}

func TestSupervisorGivesUp(t *testing.T) {
	s := &Supervisor{
		AgentPath:    "/usr/bin/false", // exits at once, never opens the socket
		Socket:       filepath.Join(shortSocketDir(t), "agent.sock"),
		MaxFailures:  3,
		RestartDelay: time.Millisecond,
		StartTimeout: 100 * time.Millisecond,
		Logf:         t.Logf,
	}
	if _, err := os.Stat(s.AgentPath); err != nil {
		t.Skip("/usr/bin/false not available")
	}
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("Run = nil, want a give-up error")
	}
}

func TestSupervisorRefusesLiveSocket(t *testing.T) {
	sock := filepath.Join(shortSocketDir(t), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	s := &Supervisor{AgentPath: sshAgentPath(t), Socket: sock, Logf: t.Logf}
	if err := s.Run(context.Background()); !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("Run = %v, want ErrSocketInUse", err)
	}
}

func countKeys(t *testing.T, sock string) int {
	t.Helper()
	conn, err := connection.GetConn(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		t.Fatal(err)
	}
	return len(keys)
}
