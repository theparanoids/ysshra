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
