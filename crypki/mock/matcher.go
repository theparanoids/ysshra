package mock

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"strings"
)

type strMatcher struct {
	x string
}

// Matches returns whether x is a match.
func (s strMatcher) Matches(x interface{}) bool {
	return strings.EqualFold(s.x, fmt.Sprintf("%v", x))
}

// String describes what the matcher matches.
func (e strMatcher) String() string {
	return fmt.Sprintf("is equal to %v", e.x)
}

// String returns a StringMatcher used for gomock to match the expected value.
func String(x interface{}) gomock.Matcher {
	return strMatcher{
		x: fmt.Sprintf("%v", x),
	}
}
