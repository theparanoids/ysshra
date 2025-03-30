package smartcard

import (
	"fmt"
	"net"

	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/common"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/gensign"
	"github.com/theparanoids/ysshra/modules"
)

const (
	// HandlerName is a unique name to identify a handler.
	// It is also appended to the cert label.
	HandlerName = "paranoids.smartcard"
)

// Handler implements gensign.Handler.
type Handler struct {
	conf        *conf
	agent       yubiagent.YubiAgent
	authModules []modules.AuthnModule
	csrModules  []modules.CSRModule
}

// NewHandler creates an SSH agent the ssh connection,
// and constructs a gensign.Handler containing the options loaded from conf.
func NewHandler(gensignConf *config.GensignConfig, conn net.Conn) (gensign.Handler, error) {
	c := new(conf)
	if err := gensignConf.ExtractHandlerConf(HandlerName, c); err != nil {
		return nil, fmt.Errorf("failed to initiialize handler %q, err: %v", HandlerName, err)
	}

	agent, err := yubiagent.NewClientFromConn(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to initiialize handler %q, err: %v", HandlerName, err)
	}

	authnModules, err := gensign.LoadAuthnModules(agent, c.AuthnModules)
	if err != nil {
		return nil, fmt.Errorf("failed to initiialize authentication modules in hander %q, err: %v", HandlerName, err)
	}

	csrModules, err := gensign.LoadCSRModules(agent, c.CSRModules, &modules.CSROption{
		KeyIdentifiers: c.KeyIdentifiers,
		KeyIDVersion:   gensignConf.KeyIDVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initiialize csr modules in handler %q, err: %v", HandlerName, err)
	}

	return &Handler{
		agent:       agent,
		authModules: authnModules,
		csrModules:  csrModules,
		conf:        c,
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

	for _, authMod := range h.authModules {
		if err := authMod.Authenticate(param); err != nil {
			return gensign.NewError(gensign.HandlerAuthN, HandlerName, err)
		}
	}
	return nil
}

func (h *Handler) Generate(param *csr.ReqParam) ([]csr.AgentKey, error) {
	var agentKeys []csr.AgentKey
	for _, csrMod := range h.csrModules {
		csrWrappers, err := csrMod.Generate(param)
		if err != nil {
			return nil, gensign.NewError(gensign.HandlerGenCSRErr, HandlerName, err)
		}
		agentKeys = append(agentKeys, csrWrappers...)
	}
	return agentKeys, nil
}
