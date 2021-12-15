package crypki

import (
	"context"
	"fmt"
	"log"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/mitchellh/mapstructure"
	"github.com/theparanoids/crypki/proto"
	pb "github.com/theparanoids/crypki/proto"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/internal/backoff"
	"go.vzbuilders.com/peng/sshra-oss/sshutils/key"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	// timeout for dialing a client connection.
	timeout        = 5.0 * time.Second
	retriesDefault = 3
)

// SignerConfig contains the signer data from the config file.
type SignerConfig struct {
	// TLSClientKeyFile is the client key to authenticate requestor's identity at Crypki.
	TLSClientKeyFile string `mapstructure:"tls_client_key_file"`
	// TLSClientKeyFile is the client cert to authenticate requestor's identity at Crypki.
	TLSClientCertFile string `mapstructure:"tls_client_cert_file"`
	// TLSCACertFiles is the list of certification authority certs to verify Crypki server cert.
	TLSCACertFiles []string `mapstructure:"tls_ca_cert_files"`
	// CrypkiEndpoints is the endpoint list of the crypki servers.
	// It is recommended to put IPs or secondary DNS name into the list.
	// Signer tries to send the certificate request to the crypki server in the order of CrypkiEndpoints.
	// If any return success, the signed certificate will be returned to the caller.
	CrypkiEndpoints []string `mapstructure:"crypki_endpoints"`
	// CrypkiPort is the port number of the crypki servers.
	CrypkiPort uint `mapstructure:"crypki_port"`
	// Retries is the number of retry times to request certificate from a crypki server endpoint.
	Retries uint `mapstructure:"retries"`
}

// Signer encapsulates the Crypki client.
type Signer struct {
	endpoints   []string
	dialOptions []grpc.DialOption
}

// NewSignerWithGensignConf creates a Signer by GensignConfig.
func NewSignerWithGensignConf(gensignConf config.GensignConfig) *Signer {
	conf := new(SignerConfig)
	if err := mapstructure.Decode(gensignConf.SignerConfig, conf); err != nil {
		log.Fatalf("failed to initiialize signer, err: %v", err)
	}
	return NewSigner(*conf)
}

// NewSigner creates a Signer by SignerConfig.
func NewSigner(conf SignerConfig) *Signer {
	tlsCfg, err := tlsConfiguration(&conf)
	if err != nil {
		log.Fatalf("failed to initialize signer, err: %v", err)
	}
	clientCreds := credentials.NewTLS(tlsCfg)

	endpoints := make([]string, len(conf.CrypkiEndpoints))
	for i, endpoint := range conf.CrypkiEndpoints {
		endpoints[i] = fmt.Sprintf("%s:%d", endpoint, conf.CrypkiPort)
	}

	retries := conf.Retries
	if retries == 0 {
		retries = retriesDefault
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithBlock(),
		// Unary interceptors can be specified as a DialOption, using
		// WithUnaryInterceptor when creating a ClientConn.
		// When a unary interceptor(s) is set on a ClientConn, gRPC
		// delegates all unary RPC invocations to the interceptor.
		// Ref: https://github.com/grpc/grpc-go/blob/master/interceptor.go#L28
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(retries),
			grpc_retry.WithBackoff(backoff.DefaultConfig.Backoff)),
		),
	}

	signer := &Signer{
		endpoints:   endpoints,
		dialOptions: dialOptions,
	}
	return signer
}

// Sign makes a signing request against Crypki Server.
func (s *Signer) Sign(ctx context.Context, request *pb.SSHCertificateSigningRequest) (certs []ssh.PublicKey, comments []string, err error) {
	for _, endpoint := range s.endpoints {
		certs, comments, err = s.postUserSSHCertificate(ctx, request, endpoint)
		if err == nil {
			return
		}
		log.Print(err)
	}
	return
}

// postUserSSHCertificate establishes the GRPC connection to the Crypki Server, and sends the signing request.
func (s *Signer) postUserSSHCertificate(ctx context.Context, csr *proto.SSHCertificateSigningRequest, endpoint string) (certs []ssh.PublicKey, comments []string, err error) {
	const apiName = "postUserSSHCertificate"
	conn, err := EstablishClientConn(ctx, endpoint, s.dialOptions...)
	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "%s: failed to establish connection, err: %v", apiName, err)
	}
	defer conn.Close()

	client := proto.NewSigningClient(conn)

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
