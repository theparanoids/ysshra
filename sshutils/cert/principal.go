// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import "strings"

const (
	// LognamePlaceholder is the placeholder for logname in a template to generate placeholders.
	LognamePlaceholder = "<logname>"
	// SplitChar is the splitter char to split the principals in a template.
	SplitChar = ","
)

// GetPrincipals returns a slice of principals based on the given principals template and the SSH logname.
func GetPrincipals(prinsTpl string, logname string) []string {
	prins := strings.ReplaceAll(prinsTpl, LognamePlaceholder, logname)
	principals := strings.Split(prins, SplitChar)
	for i := range principals {
		principals[i] = strings.TrimSpace(principals[i])
	}
	return principals
}
