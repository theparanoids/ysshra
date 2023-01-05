// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import "strings"

const (
	LognamePlaceholder = "<logname>"
	SplitChar          = ","
)

func GetPrincipals(prinsConf string, logName string) []string {
	prins := strings.ReplaceAll(prinsConf, LognamePlaceholder, logName)
	principals := strings.Split(prins, SplitChar)
	for i := range principals {
		principals[i] = strings.TrimSpace(principals[i])
	}
	return principals
}
