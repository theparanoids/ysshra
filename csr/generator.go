package csr

// Generator contains the methods to generate agent keys containing CSRs.
type Generator interface {
	// Generate generates certificate signing requests given by the request param,
	// and returns agent keys containing those CSRs.
	Generate(*ReqParam) ([]AgentKey, error)
}
