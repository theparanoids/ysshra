package config

import (
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"os"
)

type handlerConfMap map[string]interface{}

// GensignConfig stores the configuration for gensign command.
type GensignConfig struct {
	// KeyIDVersion specifies the version of KeyID.
	KeyIDVersion uint16 `json:"keyid_version"`
	// SSHCAFailureDir stores the count of the failure requests to a CA.
	SSHCAFailureDir string `json:"sshca_failure_dir"`
	// SSHCAFailureRetry is the retry times limit.
	SSHCAFailureRetry int64 `json:"sshca_failure_retry"`
	// SSHCAFailureTimeout is the maximum time period to resend the request to CA (in second).
	SSHCAFailureTimeout int64 `json:"sshca_failure_timeout"`
	// HandlerConfig is the config mapping for all the csr handlers in following format:
	// "handlers": {
	//   "$HANDLER_NAME1": {
	//     "enable": true,
	//     "$KEY": $VALUE
	//   }
	//   "$HANDLER_NAME2": {
	//     "enable": true,
	//     "$KEY": $VALUE
	//   }
	// }
	HandlerConfig map[string]handlerConfMap `json:"handlers"`
	// SignerConfig is the mapping for signer configuration.
	SignerConfig map[string]interface{} `json:"signer"`
}

// NewGensignConfig returns the gensign configuration loaded from the provided path.
func NewGensignConfig(path string) (*GensignConfig, error) {
	conf := new(GensignConfig)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// ExtractHandlerConf extracts handler config from GensignConfig by the given name.
func (g *GensignConfig) ExtractHandlerConf(name string, handlerConf interface{}) error {
	hConfMap, ok := g.HandlerConfig[name]
	if !ok {
		return fmt.Errorf("failed to find config for handler %q", name)
	}
	if err := mapstructure.Decode(hConfMap, handlerConf); err != nil {
		return fmt.Errorf("failed to decode handler conf for %q, err:%v", name, err)
	}
	return nil
}
