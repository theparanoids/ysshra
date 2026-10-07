// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Package yagent supervises a stock OpenSSH ssh-agent and keeps SSHCA
// certificates for hardware-backed (PKCS#11) keys inside that agent.
//
// Unlike the shimagent and yubiagent packages, yagent is not a proxy:
// SSH_AUTH_SOCK points directly at the inner ssh-agent, and yagent only
// connects to it as an ordinary agent client. It never holds a private key or
// a certificate in memory between operations. Certificates are attached to the
// PKCS#11 identities with the associated-certs-v00@openssh.com constraint
// (OpenSSH 9.6 or later) and backed up as public files on disk, so a
// respawned agent can be restored without any in-memory replay.
//
// See docs/design/yagent.md for the design and its trade-offs.
package yagent
