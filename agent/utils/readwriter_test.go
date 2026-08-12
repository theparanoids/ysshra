// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package utils

import (
	"bytes"
	"io"
	"testing"
)

type closableReadWriter struct {
	io.ReadWriter
}

func (closableReadWriter) Close() error {
	return nil
}

func TestWithoutCloser(t *testing.T) {
	source := closableReadWriter{
		ReadWriter: struct {
			io.Reader
			io.Writer
		}{
			Reader: bytes.NewReader(nil),
			Writer: io.Discard,
		},
	}

	transport := WithoutCloser(source)
	if _, ok := transport.(io.Closer); ok {
		t.Fatal("WithoutCloser must hide io.Closer to prevent agent.NewClient from enabling its background reader")
	}
}
