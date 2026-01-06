package authorization

import (
	"fmt"
	"log/slog"
	"time"
)

// Manage config for EntitlementPolicyCache: attributes, subject mappings, and registered resources
// Default: caching disabled, and if enabled, refresh interval defaulted to 30 seconds.
type EntitlementPolicyCacheConfig struct {
	Enabled         bool   `mapstructure:"enabled" json:"enabled" default:"false"`
	RefreshInterval string `mapstructure:"refresh_interval" json:"refresh_interval" default:"30s"`
}

type Config struct {
	Cache EntitlementPolicyCacheConfig `mapstructure:"entitlement_policy_cache" json:"entitlement_policy_cache"`

	// experimental features

	// enable entity direct entitlements that do not require subject mappings
	AllowDirectEntitlements bool `mapstructure:"allow_direct_entitlements" json:"allow_direct_entitlements" default:"false"`
}

// Validate tests for a sensible configuration
func (c *Config) Validate() error {
	duration, err := time.ParseDuration(c.Cache.RefreshInterval)
	if err != nil {
		return fmt.Errorf("failed to parse entitlement policy cache refresh interval [%s]: %w", c.Cache.RefreshInterval, err)
	}

	if c.Cache.Enabled {
		if duration < minRefreshInterval {
			return fmt.Errorf("entitlement policy cache enabled, but refresh interval [%f seconds] less than required minimum [%f seconds]: %w",
				duration.Seconds(),
				minRefreshInterval.Seconds(),
				ErrInvalidCacheConfig,
			)
		}
		if duration > maxRefreshInterval {
			return fmt.Errorf("entitlement policy cache enabled, but refresh interval [%f seconds] exceeds maximum [%f seconds]: %w",
				duration.Seconds(),
				maxRefreshInterval.Seconds(),
				ErrInvalidCacheConfig,
			)
		}
	}
	return nil
}

func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("entitlement_policy_cache",
			slog.GroupValue(
				slog.Bool("enabled", c.Cache.Enabled),
				slog.String("refresh_interval", c.Cache.RefreshInterval),
			),
		),
	)
}
