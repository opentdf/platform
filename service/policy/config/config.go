package config

import (
	"fmt"
	"log/slog"

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

func (c Config) Validate() error {
	if c.ListRequestLimitMax <= c.ListRequestLimitDefault {
		return fmt.Errorf("policy svc config request limit maximum [%d] must be greater than request limit default [%d]", c.ListRequestLimitMax, c.ListRequestLimitDefault)
	}
	return nil
}

func GetSharedPolicyConfig(cfg serviceregistry.ServiceConfig) (*Config, error) {
	policyCfg := new(Config)

	if err := defaults.Set(policyCfg); err != nil {
		return nil, fmt.Errorf("failed to set defaults for policy service config: %w", err)
	}

	// Only decode config if it exists
	if cfg != nil {
		if err := mapstructure.Decode(cfg, &policyCfg); err != nil {
			return nil, fmt.Errorf("invalid policy svc cfg [%v] %w", cfg, err)
		}
	}

	if err := policyCfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate policy config: %w", err)
	}

	slog.Debug("policy config", slog.Any("config", policyCfg))
	return policyCfg, nil
}
