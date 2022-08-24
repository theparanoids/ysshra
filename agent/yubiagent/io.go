// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxAgentResponseBytes is the maximum agent reply size that is accepted.
// This is a sanity check, not a limit in the spec.
const maxAgentResponseBytes = 16 << 20

func read(c io.Reader) (data []byte, err error) {
	var length [4]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return nil, err
	}

	l := binary.BigEndian.Uint32(length[:])
	if l > maxAgentResponseBytes {
		return nil, fmt.Errorf("data size too large: %d", l)
	}

	data = make([]byte, l)
	if _, err := io.ReadFull(c, data); err != nil {
		return nil, err
	}
	return data, nil
}

func write(c io.Writer, data []byte) (err error) {
	if len(data) > maxAgentResponseBytes {
		return fmt.Errorf("data size too large: %d", len(data))
	}

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	if _, err := c.Write(length[:]); err != nil {
		return err
	}
	if _, err := c.Write(data); err != nil {
		return err
	}
	return nil
}
