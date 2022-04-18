// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package key

import (
	"fmt"
	"os"
)

const keyFileSizeLimitation = 5 * 1024 * 1024 // 5MB.

func validateKeyFile(keyPath string) error {
	f, err := os.Open(keyPath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > keyFileSizeLimitation {
		return fmt.Errorf("size of %q excceeds the limiation, got: %v", keyPath, info.Size())
	}
	return nil
}
