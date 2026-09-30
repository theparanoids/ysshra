// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package gensign

import (
	"fmt"
	"testing"
)

func TestErrorTypeName(t *testing.T) {
	tests := []struct {
		et   ErrorType
		want string
	}{
		{Unknown, "Unknown"},
		{HandlerDisabled, "HandlerDisabled"},
		{HandlerAuthN, "HandlerAuthN"},
		{InvalidParams, "InvalidParams"},
		{HandlerGenCSRErr, "HandlerGenCSRErr"},
		{HandlerConfErr, "HandlerConfErr"},
		{AllAuthFailed, "AllAuthFailed"},
		{SignerSignErr, "SignerSignErr"},
		{AgentOpCertErr, "AgentOpCertErr"},
		{Panic, "Panic"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.et.Name(); got != tt.want {
				t.Errorf("ErrorType(%d).Name() = %q, want %q", int(tt.et), got, tt.want)
			}
		})
	}
}

func TestErrorTypeNameUnknownValue(t *testing.T) {
	et := ErrorType(99)
	want := fmt.Sprintf("ErrorType(%d)", 99)
	if got := et.Name(); got != want {
		t.Errorf("ErrorType(99).Name() = %q, want %q", got, want)
	}
}

func TestErrorTypeNameAndStringDiffer(t *testing.T) {
	// Name returns stable identifiers; String returns human sentences.
	if AllAuthFailed.Name() == AllAuthFailed.String() {
		t.Error("Name() and String() should differ for AllAuthFailed")
	}
}
