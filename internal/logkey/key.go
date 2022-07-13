// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package logkey

const (
	// MsgField and the following fields are names for structured log in gensign.
	MsgField        = "msg"
	ErrField        = "err"
	TransIDField    = "id"
	HandlerField    = "handler"
	TimeElapseField = "elapsed"

	// PrinsField and the following fields are names for structured log in handlers.
	PrinsField = "prins"
	KeyidField = "keyid"
)
