package config

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/creasty/defaults"
	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/service/pkg/config"
)

// Default refresh interval, overriden by policy config when set
var configuredRefreshInterval = 5 * time.Second

// Global policy config to share among policy services
type Config struct {
	// Default pagination list limit when not provided in request
	ListRequestLimitDefault int `mapstructure:"list_request_limit_default" default:"1000"`
	// Maximum pagination list limit allowed by policy services
	ListRequestLimitMax int `mapstructure:"list_request_limit_max" default:"2500"`

	// Interval in seconds to refresh the in-memory policy entitlement cache (attributes and subject mappings)
	CacheRefreshIntervalSeconds int `mapstructure:"cache_refresh_interval_seconds" default:"30"` // Default to 30 seconds
}

func (c Config) Validate() error {
	if c.ListRequestLimitMax <= c.ListRequestLimitDefault {
		return fmt.Errorf("policy svc config request limit maximum [%d] must be greater than request limit default [%d]", c.ListRequestLimitMax, c.ListRequestLimitDefault)
	}
	return nil
}

func GetSharedPolicyConfig(cfg config.ServiceConfig) (*Config, error) {
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

	configuredRefreshInterval = time.Duration(policyCfg.CacheRefreshIntervalSeconds) * time.Second

	slog.Debug("policy config", slog.Any("config", policyCfg))

	return policyCfg, nil
}

func GetPolicyEntitlementCacheRefreshInterval() time.Duration {
	return configuredRefreshInterval
}
