package gensign

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/theparanoids/ysshra/modules"
	"github.com/theparanoids/ysshra/modules/authn_f9_verify"
	"github.com/theparanoids/ysshra/modules/authn_slot_attest"
	"github.com/theparanoids/ysshra/modules/authn_slot_serial"
	"github.com/theparanoids/ysshra/modules/csr_smartcard_hardkey"
	"golang.org/x/crypto/ssh/agent"
)

const (
	moduleKey = "module"
)

type authnModuleCreator func(agent.Agent, map[string]interface{}) (modules.AuthnModule, error)

var authnModules = map[string]authnModuleCreator{
	authn_f9_verify.Name:   authn_f9_verify.New,
	authn_slot_attest.Name: authn_slot_attest.New,
	authn_slot_serial.Name: authn_slot_serial.New,
}

func LoadAuthnModules(agent agent.Agent, authnConf []map[string]interface{}) ([]modules.AuthnModule, error) {
	var modules []modules.AuthnModule
	for _, conf := range authnConf {
		mod, ok := conf[moduleKey]
		if !ok {
			log.Debug().Msgf("failed to find key %q in module conf %v, ignored", moduleKey, conf)
			continue
		}
		modName, ok := mod.(string)
		if !ok {
			log.Debug().Msgf("failed to cast module name in module conf %v, ignored", conf)
			continue
		}
		modCreator, ok := authnModules[modName]
		if !ok {
			log.Debug().Msgf("failed to find module %q in the module list, ignored", modName)
			continue
		}
		authnMod, err := modCreator(agent, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize %q, got error: %v", modName, err)
		}
		modules = append(modules, authnMod)
	}
	return modules, nil
}

type csrModuleCreator func(agent.Agent, map[string]interface{}, *modules.CSROption) (modules.CSRModule, error)

var csrModules = map[string]csrModuleCreator{
	csr_smartcard_hardkey.Name: csr_smartcard_hardkey.New,
}

func LoadCSRModules(agent agent.Agent, authnConf []map[string]interface{}, opt *modules.CSROption) ([]modules.CSRModule, error) {
	var mods []modules.CSRModule
	for _, conf := range authnConf {
		mod, ok := conf[moduleKey]
		if !ok {
			log.Debug().Msgf("failed to find key %q in module conf %v, ignored", moduleKey, conf)
			continue
		}
		modName, ok := mod.(string)
		if !ok {
			log.Debug().Msgf("failed to cast module name in module conf %v, ignored", conf)
			continue
		}
		modCreator, ok := csrModules[modName]
		if !ok {
			log.Debug().Msgf("failed to find module %q in the module list, ignored", modName)
			continue
		}
		csrMod, err := modCreator(agent, conf, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize %q, got error: %v", modName, err)
		}
		mods = append(mods, csrMod)
	}
	return mods, nil
}
