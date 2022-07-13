// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package csr

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	"go.vzbuilders.com/peng/sshra-oss/common"
	"go.vzbuilders.com/peng/sshra-oss/csr/transid"
	"go.vzbuilders.com/peng/sshra-oss/message"
	"go.vzbuilders.com/peng/sshra-oss/sshutils/version"
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
	// TODO: re-think do we need HandlerName field. It seems no entity relies on it.
	// HandlerName indicates which handler should handle the certificate request and generate CSRs.
	// Users may define their own handler names.
	HandlerName string
	ClientIP    string
	// LogName is the name of the user who is currently interacts with the current SSHD server.
	LogName string
	// ReqUser is the user name that sends request to RA.
	ReqUser string
	// ReqHost is the user host name that sends request to RA.
	ReqHost string
	// TransID stands for transaction ID and serves as the unique identifier for a request.
	// It should be generated on server-side right after receiving client request.
	TransID string
	// SSHClientVersion is the version of the SSH Client.
	SSHClientVersion version.Version
	// SignatureAlgo is the signing algorithm of the requested certificate.
	SignatureAlgo x509.SignatureAlgorithm
	// Attrs stores information that client passes to RA, containing attributes of SSH certificate that the client requests for.
	Attrs *message.Attributes
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

	sshClientVersion := version.NewDefaultVersion()
	if reqAttrs.SSHClientVersion != "" {
		sshClientVersion, err = version.Unmarshal(reqAttrs.SSHClientVersion)
		if err != nil {
			return nil, fmt.Errorf(`failed to unmarshal client version from SSHClientVersion=%q`, reqAttrs.SSHClientVersion)
		}
	}

	return &ReqParam{
		NamespacePolicy:  namespacePolicy,
		HandlerName:      handlerName,
		ClientIP:         clientIP,
		LogName:          logName,
		ReqUser:          reqAttrs.Username,
		ReqHost:          reqAttrs.Hostname,
		TransID:          transid.Generate(),
		SSHClientVersion: sshClientVersion,
		SignatureAlgo:    x509.SignatureAlgorithm(reqAttrs.SignatureAlgo),
		Attrs:            reqAttrs,
	}, nil
}

// parseForceCommand parses the command that invokes gensign and gets namespace policy and handler name.
// A valid command will be like this:
// /usr/bin/gensign $NAMESPACE_POLICY $HANDLER_KEYWORD
func parseForceCommand(osArgs []string) (common.NamespacePolicy, string, error) {
	// If /usr/bin/gensign is executed by OpenSSHD behind `ForceCommand`, then the command would be invoked by
	// using the user's login shell with the -c option.
	// Hence, we need to parse each argument from osArgs.
	// A typical invocation from OpenSSHD: ["gensign", "-c", "/usr/bin/gensign $NAMESPACE_POLICY $HANDLER_KEYWORD"]
	var args []string
	for _, osArg := range osArgs {
		args = append(args, strings.Split(osArg, " ")...)
	}

	l := len(args)
	if l < 3 {
		return "", "", fmt.Errorf("failed to get namespace policy and handler name from force command: %q", strings.Join(args, " "))
	} else if l > 6 {
		return "", "", fmt.Errorf("length of the force command arguments exceeds the limitation: %q", strings.Join(args, " "))
	}
	namespacePolicy := common.NamespacePolicy(args[l-2])
	if !common.ValidNamespacePolicy(namespacePolicy) {
		return "", "", fmt.Errorf("failed to validate namespace policy %q from force command: %q", namespacePolicy, strings.Join(args, " "))
	}
	return namespacePolicy, args[l-1], nil
}

// Validate is a standard way for handlers to validate the input ReqParam so that we do not need to implement the input
// validation in every function that uses ReqParam. Call this function before using the ReqParam.
// If this function returns nil, every field in ReqParam is valid in format and can be safely used. For example,
// required field is not empty, ip address string is valid in format, etc.
// A ReqParam generated by NewReqParam without error should pass this validation. If not there may be some fatal error.
func (p *ReqParam) Validate() error {
	// TODO: implement it.
	if p == nil {
		return errors.New("nil request parameter")
	}
	return nil
}
