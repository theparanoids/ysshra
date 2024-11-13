// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"context"
	"fmt"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/rs/zerolog/log"
	pb "github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/internal/backoff"
	"github.com/theparanoids/ysshra/internal/validate"
	"github.com/theparanoids/ysshra/sshutils/key"
	"github.com/theparanoids/ysshra/tlsutils"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Signer encapsulates the Crypki client.
type Signer struct {
	endpoints   []string
	dialOptions []grpc.DialOption
}

// NewSignerWithGensignConf creates a Signer by GensignConfig.
func NewSignerWithGensignConf(gensignConf config.GensignConfig) (*Signer, error) {
	conf, err := decodeSignerConfig(gensignConf.SignerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer config, err: %v", err)
	}
	return NewSigner(conf)
}

// NewSigner creates a Signer by SignerConfig.
func NewSigner(conf SignerConfig) (*Signer, error) {
	conf.populate()

	if err := validate.Validate().Struct(conf); err != nil {
		return nil, fmt.Errorf("failed to validate signer config, err: %v", err)
	}

	tlsCfg, err := tlsutils.TLSClientConfiguration(conf.TLSClientCertFile, conf.TLSClientKeyFile, conf.TLSCACertFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tls config, err :%v", err)
	}
	clientCreds := credentials.NewTLS(tlsCfg)

	endpoints := make([]string, len(conf.CrypkiEndpoints))
	for i, endpoint := range conf.CrypkiEndpoints {
		endpoints[i] = fmt.Sprintf("%s:%d", endpoint, conf.CrypkiPort)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(clientCreds),
		// Unary interceptors can be specified as a DialOption, using
		// WithUnaryInterceptor when creating a ClientConn.
		// When a unary interceptor(s) is set on a ClientConn, gRPC
		// delegates all unary RPC invocations to the interceptor.
		// Ref: https://github.com/grpc/grpc-go/blob/master/interceptor.go#L28
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(conf.Retries),
			grpc_retry.WithPerRetryTimeout(conf.PerTryTimeout),
			grpc_retry.WithBackoff(backoff.DefaultConfig.Backoff)),
		),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}

	signer := &Signer{
		endpoints:   endpoints,
		dialOptions: dialOptions,
	}
	return signer, nil
}

// Sign makes a signing request against Crypki Server.
func (s *Signer) Sign(ctx context.Context, request *pb.SSHCertificateSigningRequest) (certs []ssh.PublicKey, comments []string, err error) {
	for _, endpoint := range s.endpoints {
		certs, comments, err = s.postUserSSHCertificate(ctx, request, endpoint)
		if err == nil {
			return
		}
		log.Warn().Err(err).Msgf("failed to post request to endpoint %q", endpoint)
	}
	return
}

// postUserSSHCertificate establishes the gRPC connection to the Crypki Server, and sends the signing request.
func (s *Signer) postUserSSHCertificate(ctx context.Context, csr *pb.SSHCertificateSigningRequest, endpoint string) (certs []ssh.PublicKey, comments []string, err error) {
	const apiName = "postUserSSHCertificate"
	conn, err := EstablishClientConn(endpoint, s.dialOptions...)
	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "%s: failed to establish connection, err: %v", apiName, err)
	}
	defer conn.Close()

	client := pb.NewSigningClient(conn)

	out, err := client.PostUserSSHCertificate(ctx, csr)
	if err != nil {
		return nil, nil, fmt.Errorf("postUserSSHCertificate: failed to sign user cert, err: %v", err)
	}

	pubKeys, comments, err := key.GetPublicKeysFromBytes([]byte(out.Key))
	if err != nil {
		return pubKeys, nil, fmt.Errorf("postUserSSHCertificate: failed to parse user cert, err: %v", err)
	}

	return pubKeys, comments, nil
}

// Endpoints clones the endpoints.
func (s *Signer) Endpoints() (endpoints []string) {
	endpoints = make([]string, len(s.endpoints))
	copy(endpoints, s.endpoints)
	return
}

// DialOptions clones the dialOptions.
func (s *Signer) DialOptions() (options []grpc.DialOption) {
	options = make([]grpc.DialOption, len(s.dialOptions))
	copy(options, s.dialOptions)
	return
}
