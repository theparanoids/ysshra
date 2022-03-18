// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package mock

import (
	"fmt"
	"github.com/golang/mock/gomock"
)

type strMatcher struct {
	x string
}

// Matches returns whether x is a match.
func (s strMatcher) Matches(x interface{}) bool {
	xStr, ok := x.(string)
	if ok {
		return s.x == xStr
	}
	xStringer, ok := x.(fmt.Stringer)
	if ok {
		return s.x == xStringer.String()
	}
	return false
}

// String describes what the matcher matches.
func (s strMatcher) String() string {
	return fmt.Sprintf("is equal to %v", s.x)
}

// String returns a StringMatcher used for gomock to match the expected value.
func String(x interface{}) gomock.Matcher {
	return strMatcher{
		x: fmt.Sprintf("%v", x),
	}
}
