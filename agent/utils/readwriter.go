// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package utils

import "io"

// WithoutCloser returns a view of rw that exposes only io.Reader and io.Writer.
// Starting with golang.org/x/crypto v0.54.0, ssh/agent.NewClient starts a
// background response reader when its transport also implements io.Closer.
// Callers that perform raw request/response I/O on the same connection would
// then race with that reader, so hiding io.Closer prevents response deadlocks.
func WithoutCloser(rw io.ReadWriter) io.ReadWriter {
	return struct {
		io.Reader
		io.Writer
	}{rw, rw}
}
