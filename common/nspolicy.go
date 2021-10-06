package common

type NamespacePolicy string

const (
	NoNamespace NamespacePolicy = "NONS"
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
