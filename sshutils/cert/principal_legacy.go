// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// TODO: remove principal_legacy.go after we fully release YSSHRA.

package cert

const (
	// TouchlessLabel is the label for touchless certificates.
	TouchlessLabel = ":notouch"
	// TouchLabel is the label for touch certificates.
	TouchLabel = ":touch"
)

// GetPrincipalsLegacy returns the labeled principals based on the certificate type.
func GetPrincipalsLegacy(principals []string, certType Type) []string {
	switch certType {
	case UnknownCertType:
		return nil
	case TouchSudoCert:
		return getTouchPrincipals(principals)
	case TouchlessSudoCert:
		fallthrough
	case TouchlessCert:
		return getTouchlessPrincipals(principals)
	default:
		return principals
	}
}

func getTouchlessPrincipals(principals []string) []string {
	var labeledPrincipals []string
	for _, p := range principals {
		labeledPrincipals = append(labeledPrincipals, p+TouchlessLabel)
	}
	return labeledPrincipals
}

func getTouchPrincipals(principals []string) []string {
	var labeledPrincipals []string
	for _, p := range principals {
		labeledPrincipals = append(labeledPrincipals, p+TouchLabel)
	}
	return labeledPrincipals
}
