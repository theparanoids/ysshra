package csr

import (
	"fmt"
	"net"
	"strings"

	"go.vzbuilders.com/peng/sshra-oss/common"
	"go.vzbuilders.com/peng/sshra-oss/csr/transid"
	"go.vzbuilders.com/peng/sshra-oss/message"
)

// ReqParam stores options to invoke gensign.Handler.
type ReqParam struct {
	// TODO: rewrite this comment. It is still confusing for new users.
	// NamespacePolicy indicates the policy whether requester is authorized to request a principal under another
	// namespace, such as “Screwdriver:xxxx”.
	// Possible values:
	// 1. NSOK (Name Space OK)
	// It means the requested principals can be included in another namespace, such as xxx can be included in "Screwdriver".
	// 2. NONS (NO Name Space)
	// It means the ssh principal should start with the requested principal, such as "user:touch".
	NamespacePolicy common.NamespacePolicy
	// HandlerName indicates which handler should handle the certificate request and generate CSRs.
	// Users may define their own handler names.
	// Possible values: Regular, Smartcard, Headless.
	HandlerName string
	ClientIP    string
	LogName     string
	ReqUser     string
	ReqHost     string
	// TransID stands for transaction ID and serves as the unique identifier for a request.
	// It should be generated on server-side right after receiving client request.
	TransID          string
	SSHClientVersion string

	// attrs stores information that client passes to RA, containing attributes of SSH certificate that the client requests for.
	attrs *message.Attributes
}

// NewReqParam initializes a ReqParam properly.
// If any required field is missing or invalid, an error will be returned.
// envGetter is typically os.Getenv; osArgsGetter typically just returns os.Args.
func NewReqParam(envGetter func(string) string, osArgsGetter func() []string) (*ReqParam, error) {
	// SSH_ORIGINAL_COMMAND is set by OpenSSH when a ForceCommand directive is matched in a sshd configuration file.
	// We use it as a convenient way to let an SSH session pass parameters to an SSH server.
	sshOriginalCommand := envGetter("SSH_ORIGINAL_COMMAND")
	reqAttrs, err := message.Unmarshal(sshOriginalCommand)
	if err != nil {
		return nil, fmt.Errorf("failed to load attributes from SSH_ORIGINAL_COMMAND %q: %v", sshOriginalCommand, err)
	}

	logName := envGetter("LOGNAME")
	if logName == "" {
		return nil, fmt.Errorf("failed to load log name from LOGNAME %q", logName)
	}

	sshConnection := envGetter("SSH_CONNECTION")
	clientIP := strings.Split(sshConnection, " ")[0]
	if net.ParseIP(clientIP) == nil {
		return nil, fmt.Errorf("failed to load client IP from SSH_CONNECTION %q", sshConnection)
	}

	namespacePolicy, handlerName, err := parseForceCommand(osArgsGetter())
	if err != nil {
		return nil, err
	}

	return &ReqParam{
		NamespacePolicy:  namespacePolicy,
		HandlerName:      handlerName,
		ClientIP:         clientIP,
		LogName:          logName,
		ReqUser:          reqAttrs.Username,
		ReqHost:          reqAttrs.Hostname,
		TransID:          transid.Generate(),
		SSHClientVersion: reqAttrs.SSHClientVersion,
		attrs:            reqAttrs,
	}, nil
}

// parseForceCommand parses the command that invokes gensign and gets namespace policy and handler name.
// A valid command will be like this:
// /usr/bin/gen-sign $NAMESPACE_POLICY $HANDLER_KEYWORD
func parseForceCommand(osArgs []string) (common.NamespacePolicy, string, error) {
	l := len(osArgs)
	if l < 3 {
		return "", "", fmt.Errorf("cannot get namespace policy and handler name from force command: %q", strings.Join(osArgs, " "))
	}
	namespacePolicy := common.NamespacePolicy(osArgs[l-2])
	if !common.ValidNamespacePolicy(namespacePolicy) {
		return "", "", fmt.Errorf("cannot get valid namespace policy from force command: %q", strings.Join(osArgs, " "))
	}
	return namespacePolicy, osArgs[l-1], nil
}
