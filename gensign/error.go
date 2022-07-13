// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package gensign

import (
	"errors"
	"fmt"
	"strings"
)

// Error defines the format of an error coming from gensign handlers.
type Error struct {
	etype       ErrorType
	err         error
	handlerName string
}

// NewError returns a new Error.
// param err is optional.
func NewError(t ErrorType, handlerName string, err ...error) *Error {
	if len(err) == 0 {
		err = []error{nil}
	}
	return &Error{
		etype:       t,
		err:         err[0],
		handlerName: handlerName,
	}
}

// NewErrorWithMsg returns a new Error with a message.
func NewErrorWithMsg(t ErrorType, handlerName string, msg string) *Error {
	return &Error{
		etype:       t,
		handlerName: handlerName,
		err:         errors.New(msg),
	}
}

// Error returns the Error's string representation.
func (e Error) Error() string {
	var builder strings.Builder
	if e.handlerName != "" {
		builder.WriteString(fmt.Sprintf("%v ", e.handlerName))
	}
	builder.WriteString(e.etype.String())
	if e.err != nil {
		builder.WriteString(fmt.Sprintf(", %v", e.err.Error()))
	}
	return builder.String()
}

// Type returns the Error's ErrorType.
func (e Error) Type() ErrorType {
	return e.etype
}

// ErrorType specifies possible error types returned from CA.
type ErrorType uint8

const (
	_ ErrorType = iota
	// Unknown indicates the type of the error is unknown.
	Unknown
	// HandlerDisabled indicates the handler is disabled (by config).
	HandlerDisabled
	// HandlerAuthN indicates the handler fails with authentication.
	HandlerAuthN
	// InvalidParams indicates the request parameter is invalid.
	InvalidParams
	// HandlerGenCSRErr indicates the handler fails to generate a certificate request.
	HandlerGenCSRErr
	// HandlerConfErr indicates the handler fails to parse the handler config.
	HandlerConfErr
	// Panic indicates a panic raised from the handler.
	Panic
)

// String returns the ErrorType's string representation.
func (t ErrorType) String() string {
	switch t {
	case HandlerDisabled:
		return "handler is disabled"
	case HandlerAuthN:
		return "handler authentication error"
	case InvalidParams:
		return "handler receives invalid parameters"
	case HandlerGenCSRErr:
		return "handler fails to generate csr"
	case HandlerConfErr:
		return "handler configuration error"
	case Panic:
		return "panic"
	default:
		return "unknown error type"
	}
}

// IsErrorOfType returns true if the error matches to the given error type.
func IsErrorOfType(err interface{}, typ ErrorType) bool {
	e, ok := IsError(err)
	if !ok {
		return false
	}
	return e.Type() == typ
}

// IsError returns true if the given error is in the gensign error type.
func IsError(err interface{}) (*Error, bool) {
	if e, ok := err.(*Error); ok {
		return e, ok
	}
	return nil, false
}
