//go:build tools

// File is used to pin down the version of the tool dependency.
// See: https://github.com/go-modules-by-example/index/blob/4ea90b07f91c87190fcd691ccf8613215ca64e64/010_tools/README.md

package main

import (
	_ "github.com/square/certstrap"
)
