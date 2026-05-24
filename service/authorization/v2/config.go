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

	// PolicyFile points at a YAML/JSON snapshot of namespaces, attributes, and
	// subject mappings. When set, the authorization endpoints serve from the
	// in-memory snapshot instead of round-tripping to the policy service.
	PolicyFile string `mapstructure:"policy_file" json:"policy_file"`

	// RAR enables the RFC 8693 + RFC 9396 token-exchange endpoint at
	// POST /v2/authorization/token. Disabled by default.
	RAR RARConfig `mapstructure:"rar" json:"rar"`

	// experimental features

	// enable entity direct entitlements that do not require subject mappings
	AllowDirectEntitlements bool `mapstructure:"allow_direct_entitlements" json:"allow_direct_entitlements" default:"false"`

	// enforce strict namespaced entitlement evaluation behavior in access decisioning
	EnforceNamespacedEntitlements bool `mapstructure:"enforce_namespaced_entitlements" json:"enforce_namespaced_entitlements" default:"false"`
}

// RARConfig controls the RFC 9396 access-token issuance endpoint.
// The signing key is ephemeral in this POC: process restart rotates it and
// invalidates outstanding tokens.
type RARConfig struct {
	Enabled  bool   `mapstructure:"enabled" json:"enabled" default:"false"`
	Issuer   string `mapstructure:"issuer" json:"issuer" default:"opentdf-authorization"`
	TokenTTL string `mapstructure:"token_ttl" json:"token_ttl" default:"1h"`
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
		slog.String("policy_file", c.PolicyFile),
		slog.Any("rar",
			slog.GroupValue(
				slog.Bool("enabled", c.RAR.Enabled),
				slog.String("issuer", c.RAR.Issuer),
				slog.String("token_ttl", c.RAR.TokenTTL),
			),
		),
		slog.Bool("allow_direct_entitlements", c.AllowDirectEntitlements),
		slog.Bool("enforce_namespaced_entitlements", c.EnforceNamespacedEntitlements),
	)
}
