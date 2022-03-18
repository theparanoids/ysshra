// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package transid

import (
	"crypto/rand"
	"fmt"
)

// Generate generates 5-byte-long cryptographically secure pseudorandom transaction ID.
func Generate() string {
	transID := make([]byte, 5)
	rand.Read(transID)

	return fmt.Sprintf("%x", string(transID))
}
