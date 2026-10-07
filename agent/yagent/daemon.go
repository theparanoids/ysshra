// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"context"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/theparanoids/ysshra/agent/ssh/connection"
	"golang.org/x/crypto/ssh/agent"
)

// Config configures a Daemon.
type Config struct {
	// Dir holds the agent socket and the certificate backups (e.g. ~/.yagent).
	Dir string
	// AgentPath is the ssh-agent binary to supervise.
	AgentPath string
	// AgentArgs are extra ssh-agent arguments.
	AgentArgs []string
	// Provider is the PKCS#11 module to restore after each agent start.
	// Leave it empty to supervise an agent without hardware keys.
	Provider string
	// PIN supplies the provider PIN. Required when Provider is set.
	PIN PINSource
	// SweepInterval caps the time between expiry sweeps. Defaults to 1m.
	SweepInterval time.Duration
	// Logf defaults to log.Printf.
	Logf func(format string, args ...any)
}

// Daemon is the long-running yagent process: a supervised ssh-agent, restored
// from the certificate store after every start, plus an expiry sweeper.
type Daemon struct {
	cfg        Config
	store      *CertStore
	supervisor *Supervisor

	// plugMu serializes provider reloads: two interleaved remove/add pairs
	// would leave the agent without the provider.
	plugMu sync.Mutex
}

// NewDaemon builds a Daemon from cfg.
func NewDaemon(cfg Config) *Daemon {
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	d := &Daemon{cfg: cfg, store: &CertStore{Dir: CertDir(cfg.Dir)}}
	d.supervisor = &Supervisor{
		AgentPath: cfg.AgentPath,
		Socket:    SocketPath(cfg.Dir),
		Args:      cfg.AgentArgs,
		OnStart:   func(context.Context) error { return d.restore() },
		Logf:      cfg.Logf,
	}
	return d
}

// SocketPath is the agent socket inside dir; point SSH_AUTH_SOCK at it.
func SocketPath(dir string) string { return filepath.Join(dir, "agent.sock") }

// CertDir is the certificate backup directory inside dir.
func CertDir(dir string) string { return filepath.Join(dir, "certs") }

// Supervisor exposes the underlying supervisor, mainly for tests.
func (d *Daemon) Supervisor() *Supervisor { return d.supervisor }

// Run blocks until ctx is done or the agent cannot be kept alive.
func (d *Daemon) Run(ctx context.Context) error {
	go d.sweepLoop(ctx)
	return d.supervisor.Run(ctx)
}

// Replug reloads the provider with the current certificate store, e.g. after
// another process added certificates to it.
func (d *Daemon) Replug() error {
	if d.cfg.Provider == "" {
		return nil
	}
	d.plugMu.Lock()
	defer d.plugMu.Unlock()
	certs, err := d.plugger().Plug()
	d.cfg.Logf("[INFO] loaded %s with %d certificate(s)", d.cfg.Provider, len(certs))
	return err
}

func (d *Daemon) plugger() *Plugger {
	return &Plugger{
		Socket:   d.supervisor.Socket,
		Provider: d.cfg.Provider,
		PIN:      d.cfg.PIN,
		Store:    d.store,
	}
}

// restore runs after every agent start. A fresh agent is empty, so the
// provider and its certificates are loaded from disk, not from memory.
func (d *Daemon) restore() error {
	if _, err := d.store.Prune(time.Now()); err != nil {
		d.cfg.Logf("[WARN] prune expired certificates: %v", err)
	}
	return d.Replug()
}

func (d *Daemon) sweepLoop(ctx context.Context) {
	for {
		wait := d.cfg.SweepInterval
		if next, ok := d.store.NextExpiry(time.Now()); ok {
			// ValidBefore is inclusive, so sweep just after it.
			if untilExpiry := time.Until(next) + time.Second; untilExpiry < wait {
				wait = max(untilExpiry, 0)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		d.sweep()
	}
}

func (d *Daemon) sweep() {
	conn, err := connection.GetConn(d.supervisor.Socket)
	if err != nil {
		return // agent is restarting; restore will prune the store
	}
	defer func() { _ = conn.Close() }()
	removed, err := Sweep(agent.NewClient(conn), d.store, time.Now())
	if err != nil {
		d.cfg.Logf("[WARN] sweep expired certificates: %v", err)
	}
	for _, cert := range removed {
		d.cfg.Logf("[INFO] removed expired certificate %q", cert.KeyId)
	}
}
