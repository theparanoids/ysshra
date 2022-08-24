// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//go:build !windows
// +build !windows

package yubiagent

import "os/exec"

const pivTool = "yubico-piv-tool"

func getPivToolPath() (string, error) {
	return exec.LookPath(pivTool)
}
