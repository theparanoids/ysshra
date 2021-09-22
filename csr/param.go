package csr

// ReqParam stores options to invoke gensign.Handler.
type ReqParam struct {
	// Following Fields are required.
	// AuthComment indicates what kind of authentication the current requester has passed.
	// There are currently 3 possible values: NSOK/NONS/POGO.
	AuthComment string
	ClientIP    string
	LogName     string
	ReqUser     string
	ReqHost     string
	// TransID stands for transaction ID and serves as the unique identifier for a request.
	// It should be generated on server-side right after receiving client request.
	TransID string
	// TODO: add client version

	// args stored the original values of the arguments, including optional values.
	args map[string]string
}

// NewReqParam initializes a ReqParam properly.
// The format of args is expected to be a list of space separated key[=value],
// e.g. "IFVer=5 req=example@somehost.yahoo.com IPs=1.2.3.4,5.6.7.8 privKeyNeeded".
// If any required field is missing from the args, an error will be returned.
func NewReqParam(args string) (*ReqParam, error) {
	rp := &ReqParam{}
	// TODO: Initialize the exported fields.
	return rp, nil
}
