package config

import (
	"fmt"

	"github.com/creasty/defaults"
	"github.com/mitchellh/mapstructure"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

// Global policy config to share among policy services
type Config struct {
	// Default pagination list limit when not provided in request
	ListRequestLimitDefault int `mapstructure:"list_request_limit_default" default:"1000"`
	// Maximum pagination list limit allowed by policy services
	ListRequestLimitMax int `mapstructure:"list_request_limit_max" default:"2500"`
}

func GetSharedPolicyConfig(srp serviceregistry.RegistrationParams) *Config {
	policyCfg := new(Config)

	if err := defaults.Set(policyCfg); err != nil {
		panic(fmt.Errorf("failed to set defaults for policy service config: %w", err))
	}

	// Only decode config if it exists
	if srp.Config != nil {
		if err := mapstructure.Decode(srp.Config, &policyCfg); err != nil {
			panic(fmt.Errorf("invalid policy svc cfg [%v] %w", srp.Config, err))
		}
	}

	if policyCfg.ListRequestLimitMax <= policyCfg.ListRequestLimitDefault {
		panic(fmt.Errorf("policy svc config request limit maximum [%d] must be greater than request limit default [%d]", policyCfg.ListRequestLimitMax, policyCfg.ListRequestLimitDefault))
	}

	return policyCfg
}
