package crypki

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SSHUserKeyID - key identifier for user ssh certificate signing key.
const SSHUserKeyID = "ssh-user-key"

// GetDefaultExtension returns default extensions for user SSH certificate.
func GetDefaultExtension() map[string]string {
	exts := make(map[string]string)
	exts["permit-pty"] = ""
	exts["permit-X11-forwarding"] = ""
	exts["permit-agent-forwarding"] = ""
	exts["permit-port-forwarding"] = ""
	exts["permit-user-rc"] = ""
	return exts
}

// EstablishClientConn establishes a GRPC connection to the crypki endpoint.
func EstablishClientConn(ctx context.Context, endpoint string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err = grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to dial to Crypki: %v", err)
	}
	return conn, nil
}
