// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Command yagent is a proof of concept of the yagent design: it supervises a
// stock OpenSSH ssh-agent and keeps PKCS#11-backed SSH certificates inside it.
//
//	yagent run -pkcs11 /path/to/module.so     # start the daemon
//	eval "$(yagent env)"                       # SSH_AUTH_SOCK -> inner agent
//	yagent add-cert -pkcs11 /path/to/module.so cert.pub...
//
// The PIN is read from the environment variable named by -pin-env, which is
// for demos only. See docs/design/yagent.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/theparanoids/ysshra/agent/yagent"
	"golang.org/x/crypto/ssh"
)

const usage = `usage:
  yagent run     [-dir DIR] [-agent PATH] [-P ALLOWLIST] [-pkcs11 MODULE] [-pin-env VAR]
  yagent add-cert [-dir DIR] [-pkcs11 MODULE] [-pin-env VAR] CERT...
  yagent env     [-dir DIR]
`

type flags struct {
	fs        *flag.FlagSet
	dir       string
	agentPath string
	allowlist string
	provider  string
	pinEnv    string
}

func newFlags(name string) *flags {
	f := &flags{fs: flag.NewFlagSet(name, flag.ExitOnError)}
	f.fs.StringVar(&f.dir, "dir", "~/.yagent", "yagent state directory (agent socket and certificate backups)")
	f.fs.StringVar(&f.agentPath, "agent", "ssh-agent", "ssh-agent binary to supervise (OpenSSH 9.6 or later)")
	f.fs.StringVar(&f.allowlist, "P", "", "ssh-agent -P allowlist of PKCS#11 module paths")
	f.fs.StringVar(&f.provider, "pkcs11", "", "PKCS#11 module to load into the agent")
	f.fs.StringVar(&f.pinEnv, "pin-env", "YAGENT_PIN", "environment variable holding the PKCS#11 PIN (demo only)")
	return f
}

func (f *flags) stateDir() string {
	if rest, ok := strings.CutPrefix(f.dir, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("resolve home directory: %v", err)
		}
		return filepath.Join(home, rest)
	}
	return f.dir
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	f := newFlags(os.Args[1])
	_ = f.fs.Parse(os.Args[2:])

	var err error
	switch os.Args[1] {
	case "run":
		err = run(f)
	case "add-cert":
		err = addCert(f, f.fs.Args())
	case "env":
		sock := yagent.SocketPath(f.stateDir())
		fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", sock)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}

func run(f *flags) error {
	dir := f.stateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	var args []string
	if f.allowlist != "" {
		args = append(args, "-P", f.allowlist)
	}
	d := yagent.NewDaemon(yagent.Config{
		Dir:       dir,
		AgentPath: f.agentPath,
		AgentArgs: args,
		Provider:  f.provider,
		PIN:       yagent.EnvPIN(f.pinEnv),
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP reloads the provider with whatever is in the certificate store.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := d.Replug(); err != nil {
				log.Printf("[WARN] reload on SIGHUP: %v", err)
			}
		}
	}()

	log.Printf("[INFO] yagent: export SSH_AUTH_SOCK=%s", yagent.SocketPath(dir))
	return d.Run(ctx)
}

// addCert backs up the certificates and reloads the provider once with the
// whole set, so a batch of certificates costs a single PIN verification.
func addCert(f *flags, paths []string) error {
	if len(paths) == 0 {
		return errors.New("add-cert: no certificate files given")
	}
	if f.provider == "" {
		return errors.New("add-cert: -pkcs11 is required")
	}
	dir := f.stateDir()
	store := &yagent.CertStore{Dir: yagent.CertDir(dir)}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("%s: not an SSH certificate", path)
		}
		if err := store.Put(cert, comment); err != nil {
			return err
		}
	}

	p := &yagent.Plugger{
		Socket:   yagent.SocketPath(dir),
		Provider: f.provider,
		PIN:      yagent.EnvPIN(f.pinEnv),
		Store:    store,
	}
	certs, err := p.Plug()
	if err != nil {
		return err
	}
	fmt.Printf("loaded %s with %d certificate(s)\n", f.provider, len(certs))
	return nil
}
