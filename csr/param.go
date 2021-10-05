package csr

import (
	"fmt"
	"net"
	"os"
	"strings"

	"go.vzbuilders.com/peng/sshra-oss/message"
	"go.vzbuilders.com/peng/sshra-oss/pkg/transid"
)

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

	// attrs stores information that client passes to RA, containing attributes of SSH certificate that the client request for.
	attrs *message.Attributes
}

// TODO: Add test for this function.
// NewReqParam initializes a ReqParam properly.
// The format of args is expected to be a list of space separated key[=value],
// e.g. "IFVer=5 req=example@somehost.yahoo.com IPs=1.2.3.4,5.6.7.8 privKeyNeeded".
// If any required field is missing from the args, an error will be returned.
func NewReqParam() (*ReqParam, error) {
	// SSH_ORIGINAL_COMMAND is set by OpenSSH when a ForceCommand directive is matched in a sshd configuration file.
	// We use it as a convenient way to let an SSH session pass parameters to an SSH server.
	sshOriginalCommand := os.Getenv("SSH_ORIGINAL_COMMAND")
	reqAttrs, err := message.Unmarshal(sshOriginalCommand)
	if err != nil {
		return nil, fmt.Errorf("failed to load attributes from SSH_ORIGINAL_COMMAND %q: %v", sshOriginalCommand, err)
	}
	sshConnection := os.Getenv("SSH_CONNECTION")
	logName := os.Getenv("LOGNAME")
	if logName == "" {
		return nil, fmt.Errorf("failed to load log name from LOGNAME %q", logName)
	}
	reqParam := &ReqParam{
		// TODO: extend AuthComment to NamespacePolicy and HandlerName.
		// AuthComment: os.Args[len(os.Args)-1],
		ClientIP: strings.Split(sshConnection, " ")[0],
		LogName:  logName,
		ReqUser:  reqAttrs.Username,
		ReqHost:  reqAttrs.Hostname,
		TransID:  transid.Generate(),
		attrs:    reqAttrs,
	}
	if net.ParseIP(reqParam.ClientIP) == nil {
		return nil, fmt.Errorf("failed to load client IP from SSH_CONNECTION %q", sshConnection)
	}
	return reqParam, nil
}
