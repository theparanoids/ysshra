// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
	conn, err = grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to dial to Crypki: %v", err)
	}
	return conn, nil
}
