// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package regular

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/theparanoids/crypki/proto"
	agssh "go.vzbuilders.com/peng/sshra-oss/agent/ssh"
	"go.vzbuilders.com/peng/sshra-oss/common"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/crypki"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/internal/logkey"
	"go.vzbuilders.com/peng/sshra-oss/keyid"
	"golang.org/x/crypto/ssh"
	ag "golang.org/x/crypto/ssh/agent"
)

const (
	// HandlerName is a unique name to identify a handler.
	// It is also appended to the cert label.
	HandlerName = "paranoids.regular"
	// IsForHumanUser indicates whether this handler should be used for a human user.
	IsForHumanUser = true
)

// Handler implements gensign.Handler.
type Handler struct {
	certValiditySec uint64
	agent           ag.Agent
	conf            *conf
}

// NewHandler creates an SSH agent the ssh connection,
// and constructs a gensign.Handler containing the options loaded from conf.
func NewHandler(gensignConf *config.GensignConfig, conn net.Conn) (gensign.Handler, error) {
	c := NewDefaultConf()
	if err := gensignConf.ExtractHandlerConf(HandlerName, c); err != nil {
		return nil, fmt.Errorf("failed to initiialize handler %q, err: %v", HandlerName, err)
	}

	agent := ag.NewClient(conn)

	return &Handler{
		agent:           agent,
		certValiditySec: c.CertValiditySec,
		conf:            c,
	}, nil
}

// Name returns the name of the handler.
func (h *Handler) Name() string {
	return HandlerName
}

// Authenticate succeeds if the user is allowed to use request the certificate based on the public key on server side's directory.
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

	if err := h.challengePubKey(param); err != nil {
		return gensign.NewError(gensign.HandlerAuthN, HandlerName, err)
	}
	return nil
}

// Generate implements csr.Generator.
// TODO: add tests and wrap all errors as gensign errors.
func (h *Handler) Generate(param *csr.ReqParam) ([]csr.AgentKey, error) {
	err := param.Validate()
	if err != nil {
		return nil, gensign.NewError(gensign.InvalidParams, HandlerName, err)
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

	agentKey, err := h.generateAgentKey()
	if err != nil {
		return nil, gensign.NewError(gensign.HandlerGenCSRErr, HandlerName, err)
	}

	keyIdentifier, ok := h.conf.KeyIdentifiers[param.Attrs.CAPubKeyAlgo]
	if !ok {
		err := fmt.Errorf("unsupported CA public key algorithm %q", param.Attrs.CAPubKeyAlgo)
		return nil, gensign.NewError(gensign.HandlerConfErr, HandlerName, err)
	}

	request := &proto.SSHCertificateSigningRequest{
		KeyMeta:    &proto.KeyMeta{Identifier: keyIdentifier},
		Extensions: crypki.GetDefaultExtension(),
		Validity:   h.certValiditySec,
		Principals: kid.Principals,
		PublicKey:  string(ssh.MarshalAuthorizedKey(agentKey.PublicKey())),
	}

	request.KeyId, err = kid.Marshal()
	if err != nil {
		return nil, gensign.NewError(gensign.HandlerGenCSRErr, HandlerName, err)
	}

	agentKey.addCSR(request)

	log.Info().Str(logkey.TransIDField, param.TransID).
		Str(logkey.HandlerField, HandlerName).
		Strs(logkey.PrinsField, request.Principals).
		Str(logkey.KeyidField, request.KeyId).
		Msgf("CSRs successfully generated")

	return []csr.AgentKey{agentKey}, nil
}

func (h *Handler) challengePubKey(param *csr.ReqParam) error {
	pubKeyBytes, err := getPubKeyBytes(h.conf.PubKeyDir, param.LogName)
	if err != nil {
		return fmt.Errorf("failed to read pubkey: %v", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse pubkey: %v, pubkey: %q", err, string(pubKeyBytes))
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

func (h *Handler) generateAgentKey() (*csrAgentKey, error) {
	agentKeyOpt := agssh.DefaultKeyOpt
	agentKeyOpt.KeyRefreshFilter = keyFilter
	agentKeyOpt.PrivateKeyValiditySec = uint32(h.conf.CertValiditySec) + uint32(time.Hour.Seconds())
	agentKeyOpt.CertLabel = fmt.Sprintf("%s-%s", HandlerName, "cert")
	agentKey, err := agssh.NewSSHAgentKeyWithOpt(h.agent, agentKeyOpt)
	if err != nil {
		return nil, err
	}
	return &csrAgentKey{
		AgentKey: agentKey,
	}, nil
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
	pubKeyPath := path.Join(pubKeyDirPath, logName+".pub")
	if _, err := os.Stat(pubKeyPath); err != nil {
		pubKeyPath = path.Join(pubKeyDirPath, logName)
	}
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		return "", err
	}
	return pubKeyPath, nil
}

func keyFilter(key *ag.Key) bool {
	return strings.Contains(key.Comment, HandlerName)
}
