// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package backoff

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	t.Parallel()
	config := &Config{BaseDelay: 300.0 * time.Millisecond,
		Multiplier: 2.0,
		Jitter:     0,
		MaxDelay:   1.0 * time.Second}
	// if retry is 0, return value should be same as BaseDelay
	got := config.Backoff(0)
	if got != config.BaseDelay {
		t.Errorf("unexpected error for retry 0, expected %v got %v", config.BaseDelay, got)
	}

	// if retry == 3 with Jitter = 0 backoff will be less than MaxDelay
	got = config.Backoff(1)
	if got > config.MaxDelay {
		t.Errorf("unexpected error for retry 3, expected value less than %v got %v", config.MaxDelay, got)
	}

	// if retry == 3 with Jitter = 0.2, backoff will be more than BaseDelay
	config.Jitter = 0.2
	got = config.Backoff(3)
	if got <= config.BaseDelay {
		t.Errorf("unexpected error for retry 3, expected value greater than %v got %v", config.BaseDelay, got)
	}
}
