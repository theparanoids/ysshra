// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/theparanoids/ysshra/agent/ssh/connection"
)

// Supervisor keeps an ssh-agent process listening on a fixed socket, so
// SSH_AUTH_SOCK can point at that socket for the lifetime of the session.
type Supervisor struct {
	// AgentPath is the ssh-agent binary. It must be OpenSSH 9.6 or later for
	// certificates to be attached to PKCS#11 keys.
	AgentPath string
	// Socket is where the agent listens (ssh-agent -a).
	Socket string
	// Args are extra ssh-agent arguments, such as -P <provider allowlist>.
	Args []string
	// OnStart runs after each (re)started agent accepts connections. Its
	// error is logged, not fatal: an agent without certificates is still
	// better than no agent.
	OnStart func(ctx context.Context) error

	// MaxFailures is how many consecutive failures end supervision; it
	// should not exceed the token's PIN retry budget when OnStart spends a
	// PIN. Defaults to 3.
	MaxFailures int
	// MinHealthyUptime resets the failure streak after a long-lived agent
	// dies, so one unrelated crash is not treated as a crash loop. Defaults
	// to 30s.
	MinHealthyUptime time.Duration
	// RestartDelay is the pause before a respawn. Defaults to 500ms.
	RestartDelay time.Duration
	// StartTimeout bounds how long a new agent may take to open its socket.
	// Defaults to 10s.
	StartTimeout time.Duration
	// Logf defaults to log.Printf.
	Logf func(format string, args ...any)

	mu  sync.Mutex
	pid int
}

// ErrSocketInUse is returned when another live agent already owns Socket.
var ErrSocketInUse = errors.New("yagent: socket is already served by a live agent")

// Pid returns the process ID of the running agent, or 0.
func (s *Supervisor) Pid() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pid
}

// Run starts the agent and restarts it whenever it exits, until ctx is done or
// the agent fails MaxFailures times in a row.
func (s *Supervisor) Run(ctx context.Context) error {
	s.setDefaults()
	failures := 0
	for {
		startedAt := time.Now()
		cmd, err := s.start(ctx)
		if errors.Is(err, ErrSocketInUse) {
			return err
		}
		if err == nil {
			s.Logf("[INFO] ssh-agent started on %s (pid %d)", s.Socket, cmd.Process.Pid)
			if s.OnStart != nil {
				if err := s.OnStart(ctx); err != nil {
					s.Logf("[WARN] restore after agent start: %v", err)
				}
			}
			err = cmd.Wait()
			s.setPid(0)
		}
		if ctx.Err() != nil {
			return nil
		}

		if time.Since(startedAt) >= s.MinHealthyUptime {
			failures = 0
		}
		failures++
		if failures >= s.MaxFailures {
			return fmt.Errorf("yagent: ssh-agent failed %d times in a row, giving up: %v", failures, err)
		}
		s.Logf("[WARN] ssh-agent exited (failure %d/%d): %v; restarting", failures, s.MaxFailures, err)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.RestartDelay):
		}
	}
}

func (s *Supervisor) setDefaults() {
	if s.MaxFailures <= 0 {
		s.MaxFailures = 3
	}
	if s.MinHealthyUptime <= 0 {
		s.MinHealthyUptime = 30 * time.Second
	}
	if s.RestartDelay <= 0 {
		s.RestartDelay = 500 * time.Millisecond
	}
	if s.StartTimeout <= 0 {
		s.StartTimeout = 10 * time.Second
	}
	if s.Logf == nil {
		s.Logf = log.Printf
	}
}

func (s *Supervisor) setPid(pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pid = pid
}

// start launches ssh-agent in the foreground and waits for its socket.
func (s *Supervisor) start(ctx context.Context) (*exec.Cmd, error) {
	if err := clearStaleSocket(s.Socket); err != nil {
		return nil, err
	}

	args := append(append([]string(nil), s.Args...), "-D", "-a", s.Socket)
	cmd := exec.CommandContext(ctx, s.AgentPath, args...)
	// SIGTERM lets ssh-agent remove its socket; WaitDelay escalates to
	// SIGKILL and stops an orphaned ssh-pkcs11-helper holding the output
	// pipe from blocking Wait forever.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s.setPid(cmd.Process.Pid)
	go s.logLines("[ssh-agent] ", out)

	if err := waitForSocket(ctx, s.Socket, s.StartTimeout); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		s.setPid(0)
		return nil, err
	}
	return cmd, nil
}

func (s *Supervisor) logLines(prefix string, r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		s.Logf("%s%s", prefix, sc.Text())
	}
}

// clearStaleSocket removes a socket file left by an agent that was killed
// before it could clean up, but refuses to touch one a live agent serves.
func clearStaleSocket(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if conn, err := connection.GetConn(path); err == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: %s", ErrSocketInUse, path)
	}
	return os.Remove(path)
}

func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if conn, err := connection.GetConn(path); err == nil {
			return conn.Close()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("yagent: ssh-agent did not open %s: %w", path, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
