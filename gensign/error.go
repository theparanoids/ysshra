package gensign

import (
	"errors"
	"fmt"
	"strings"
)

type Error struct {
	type_       ErrorType
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
		type_:       t,
		err:         err[0],
		handlerName: handlerName,
	}
}

// NewErrorWithMsg returns a new Error with a message.
func NewErrorWithMsg(t ErrorType, handlerName string, msg string) *Error {
	return &Error{
		type_:       t,
		handlerName: handlerName,
		err:         errors.New(msg),
	}
}

// Error returns the Error's string representation.
func (e Error) Error() string {
	var builder strings.Builder
	if e.handlerName != "" {
		builder.WriteString(fmt.Sprintf("[%v]", e.handlerName))
	}
	builder.WriteString(e.type_.String())
	if e.err != nil {
		builder.WriteString(fmt.Sprintf(", %v", e.err.Error()))
	}
	return builder.String()
}

// Type returns the Error's ErrorType.
func (e Error) Type() ErrorType {
	return e.type_
}

// ErrorType specifies possible error types returned from CA
type ErrorType uint8

const (
	_ ErrorType = iota
	Unknown
	HandlerDisabled
	HandlerAuthN
	InvalidParams
	HandlerGenCSRErr
	HandlerConfErr
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

func IsErrorOfType(err interface{}, typ ErrorType) bool {
	e, ok := IsError(err)
	if !ok {
		return false
	}
	return e.Type() == typ
}

func IsError(err interface{}) (*Error, bool) {
	if e, ok := err.(*Error); ok {
		return e, ok
	}
	return nil, false
}
