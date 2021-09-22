package signer

import (
	pb "github.com/theparanoids/crypki/proto"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"golang.org/x/crypto/ssh"
)

// CrypkiSigner encapsulates the Crypki client.
type CrypkiSigner struct{}

// NewCrypkiSigner creates a CrypkiSigner by GensignConfig.
func NewCrypkiSigner(conf *config.GensignConfig) *CrypkiSigner {
	return nil
}

// Sign makes a signing request to Crypki Server.
func (s *CrypkiSigner) Sign(transID string, request *pb.SSHCertificateSigningRequest) (cert ssh.PublicKey, comment string, err error) {
	// TODO: invoke crypki server.
	return nil, "", nil
}
