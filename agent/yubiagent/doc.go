// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Package yubiagent implements a protocol to communicate with YubiKey via a forwarded
// ssh-agent. It provides a client agent and a server agent. The server side wraps the
// common YubiKey operations in customized ssh-agent protocol. The client follows this
// protocol to manipulate YubiKey.
package yubiagent
