// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

const yubicoPivToolPath = `C:\Program Files\Yubico\Yubico PIV Tool\bin\yubico-piv-tool.exe`

func getPivToolPath() (string, error) {
	return yubicoPivToolPath, nil
}
