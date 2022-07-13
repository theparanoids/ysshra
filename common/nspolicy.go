// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package common

// NamespacePolicy indicates whether a requester is authorized to request a certificate with principal under another namespace.
type NamespacePolicy string

const (
	// NoNamespace indicates the ssh principal should start with the requested principal.
	// For example, user1 is authorized to request a cert with touch principal "user1:touch".
	NoNamespace NamespacePolicy = "NONS"
	// NamespaceOK indicates the ssh principal can be included in another principal.
	// For example, user1 is authorized to request a principal for jenkins usage: "jenkins:user1".
	NamespaceOK NamespacePolicy = "NSOK"
)

var namespacePolicies = map[NamespacePolicy]struct{}{
	NoNamespace: {},
	NamespaceOK: {},
}

// ValidNamespacePolicy checks if policy is a valid namespace policy.
func ValidNamespacePolicy(policy NamespacePolicy) bool {
	_, ok := namespacePolicies[policy]
	return ok
}
