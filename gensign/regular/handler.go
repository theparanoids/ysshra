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
	"go.vzbuilders.com/peng/sshra-oss/common"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/crypki"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/internal/cert/broker"
	"go.vzbuilders.com/peng/sshra-oss/keyid"
)

const (
	// HandlerName is a unique name to identify a handler.
	HandlerName = "Regular"
	// IsForHumanUser indicates whether this handler should be used for a human user.
	IsForHumanUser         = true
	defaultCertValiditySec = 12 * 3600 // 12 hours
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

// TODO: rewrite the comment here. The comment may not include OTP.
// Authenticate succeeds if the user is allowed to use OTP to get a certificate.
func (h *Handler) Authenticate(param *csr.ReqParam) error {
	err := param.Validate()
	if err != nil {
		return gensign.NewError(gensign.InvalidParams, HandlerName, err)
	}

	if param.NamespacePolicy != common.NoNamespace {
		return gensign.NewErrorWithMsg(gensign.HandlerAuthN, HandlerName, fmt.Sprintf("want namespace policy %s, but got %s", common.NoNamespace, param.NamespacePolicy))
	}
	if param.Attrs.HardKey {
		return gensign.NewErrorWithMsg(gensign.HandlerAuthN, HandlerName, "do not support hard key validation")
	}

	if !h.enabled {
		return gensign.NewError(gensign.HandlerDisabled, HandlerName)
	}

	if err := h.challengePubKey(param); err != nil {
		return gensign.NewError(gensign.HandlerAuthN, HandlerName, err)
	}
	return nil
}

// TODO: add tests and wrap all errors as gensign errors.
// Generate implements csr.Generator.
func (h *Handler) Generate(param *csr.ReqParam) ([]*proto.SSHCertificateSigningRequest, error) {
	err := param.Validate()
	if err != nil {
		return nil, gensign.NewError(gensign.InvalidParams, HandlerName, err)
	}

	pubKeyBytes, err := getPubKeyBytes(h.pubKeyDirPath, param.LogName)
	if err != nil {
		return nil, err
	}

	kid := &keyid.KeyID{
		Principals:    []string{param.LogName},
		TransID:       param.TransID,
		ReqUser:       param.ReqUser,
		ReqIP:         param.ClientIP,
		ReqHost:       param.ReqHost,
		Version:       keyid.DefaultVersion,
		IsFirefighter: false,
		IsHWKey:       false,
		IsHeadless:    false,
		IsNonce:       false,
		Usage:         keyid.AllUsage,
		TouchPolicy:   keyid.NeverTouch,
	}

	request := &proto.SSHCertificateSigningRequest{
		KeyMeta:    &proto.KeyMeta{Identifier: crypki.SSHUserKeyID},
		Extensions: crypki.GetDefaultExtension(),
		Validity:   defaultCertValiditySec,
		Principals: kid.Principals,
		PublicKey:  string(pubKeyBytes),
	}

	request.KeyId, err = kid.Marshal()
	if err != nil {
		return nil, err
	}
	return []*proto.SSHCertificateSigningRequest{request}, nil
}

func (h *Handler) challengePubKey(param *csr.ReqParam) error {
	pubKeyBytes, err := getPubKeyBytes(h.pubKeyDirPath, param.LogName)
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

// getPubKeyBytes returns the public key for the logName in []byte format.
func getPubKeyBytes(pubKeyDirPath string, logName string) ([]byte, error) {
	pubKeyPath, err := lookupPubKeyFile(pubKeyDirPath, logName)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(pubKeyPath)
}

// lookupPubKeyFile returns the public key path for the logName.
func lookupPubKeyFile(pubKeyDirPath string, logName string) (string, error) {
	pubKeyPath := path.Join(pubKeyDirPath, logName)
	if _, err := os.Stat(pubKeyPath); err != nil {
		pubKeyPath = path.Join(pubKeyDirPath, logName+".pub")
	}
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		return "", err
	}
	return pubKeyPath, nil
}
