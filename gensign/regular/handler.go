package regular

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"path"

	"golang.org/x/crypto/ssh"
	ag "golang.org/x/crypto/ssh/agent"

	"github.com/theparanoids/crypki/proto"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/internal/cert/broker"
)

const (
	// HandlerName is a unique name to identify a handler.
	HandlerName = "Regular"
	// IsForHumanUser indicates whether this handler should be used for a human user.
	IsForHumanUser = true
)

// Handler implements gensign.Handler.
type Handler struct {
	*gensign.BaseHandler
	// enabled indicates whether the handler is enabled or not.
	enabled bool
	// pubKeyDirPath specifies the directory path which stores users' public keys.
	pubKeyDirPath string
	agent         ag.Agent
}

// NewHandler creates a certificate broker via the ssh connection,
// and constructs a gensign.Handler containing the options loaded from conf.
func NewHandler(gensignConf *config.GensignConfig, conn net.Conn) gensign.Handler {
	c := new(conf)
	if err := gensignConf.ExtractHandlerConf(HandlerName, c); err != nil {
		log.Printf("Warning: failed to initiialize handler %q, disabled the handler by default, err: %v", HandlerName, err)
		return &Handler{enabled: false}
	}

	b := broker.NewSSHCertBroker(conn)
	return &Handler{
		BaseHandler:   gensign.NewBaseHandler(b, HandlerName, IsForHumanUser),
		enabled:       c.Enable,
		pubKeyDirPath: c.PubKeyDir,
		agent:         ag.NewClient(conn),
	}
}

// Authenticate succeeds if the user is allowed to use OTP to get a certificate.
func (h *Handler) Authenticate(param *csr.ReqParam) error {
	if !h.enabled {
		return gensign.NewError(gensign.HandlerDisabled, HandlerName)
	}
	// TODO:
	// Check request param.
	if err := h.challengePubKey(param); err != nil {
		return gensign.NewError(gensign.HandlerAuthN, HandlerName, err)
	}
	return gensign.NewErrorWithMsg(gensign.Unknown, HandlerName, "not implemented")
}

// Generate implements csr.Generator.
func (h *Handler) Generate(param *csr.ReqParam) ([]*proto.SSHCertificateSigningRequest, error) {
	// TODO
	// 1. Generate new key pair
	// 2. Process keyId
	// 3. Append certificate requests to the return slice
	return nil, nil
}

func (h *Handler) challengePubKey(param *csr.ReqParam) error {
	pubKeyPath, err := h.lookupPubKeyFile(param.LogName)
	if err != nil {
		return err
	}

	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return err
	}

	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		return fmt.Errorf("cannot generate random challenge: %v", err)
	}
	sig, err := h.agent.Sign(pubKey, data)
	if err != nil {
		return fmt.Errorf("cannot sign the challenge: %v", err)
	}
	return pubKey.Verify(data, sig)
}

// lookupPubKeyFile returns the public key path for the logName.
func (h *Handler) lookupPubKeyFile(logName string) (string, error) {
	pubKeyPath := path.Join(h.pubKeyDirPath, logName)
	if _, err := os.Stat(pubKeyPath); err != nil {
		pubKeyPath = path.Join(h.pubKeyDirPath, logName+".pub")
	}
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		return "", err
	}
	return pubKeyPath, nil
}
