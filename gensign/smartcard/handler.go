package smartcard

import (
	"fmt"
	"github.com/theparanoids/ysshra/modules"
	"net"

	"github.com/theparanoids/ysshra/agent/yubiagent"
	"github.com/theparanoids/ysshra/common"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/gensign"
)

const (
	// HandlerName is a unique name to identify a handler.
	// It is also appended to the cert label.
	HandlerName = "paranoids.smartcard"
)

type slotAuthModules []modules.SlotAuthModule

type csrModules []modules.CSRModule

// Handler implements gensign.Handler.
type Handler struct {
	conf            *conf
	agent           yubiagent.YubiAgent
	authModules     []modules.AuthModule
	slotAuthModules map[*yubiagent.SlotAgent]slotAuthModules
	slotCSRModule   map[*yubiagent.SlotAgent]csrModules
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

	return &Handler{
		agent: agent,
		conf:  c,
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
		if err := authMod.Authenticate(h.agent, param); err != nil {
			return gensign.NewError(gensign.HandlerAuthN, HandlerName, err)
		}
	}

	for keySlot, authModules := range h.slotAuthModules {
		for _, authMod := range authModules {
			if err := authMod.Authenticate(keySlot, param); err != nil {
				return gensign.NewError(gensign.HandlerAuthN, HandlerName, err)
			}
		}
	}
	return nil
}

func (h *Handler) Generate(param *csr.ReqParam) ([]csr.AgentKey, error) {
	var agentKeys []csr.AgentKey
	for slot, csrMods := range h.slotCSRModule {
		for _, csrMod := range csrMods {
			csrs, err := csrMod.Generate(slot.Agent(), param)
			if err != nil {
				return nil, gensign.NewError(gensign.HandlerGenCSRErr, HandlerName, err)
			}
			slot.RegisterCSRs(csrs)
		}
		agentKeys = append(agentKeys, slot)
	}
	return agentKeys, nil
}
