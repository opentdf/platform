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

type RequestLimitsConfig struct {
	ResourceAttributeValuesMax   int `mapstructure:"resource_attribute_values_max" json:"resource_attribute_values_max" default:"20"`
	EntityChainEntitiesMax       int `mapstructure:"entity_chain_entities_max" json:"entity_chain_entities_max" default:"10"`
	FulfillableObligationFqnsMax int `mapstructure:"fulfillable_obligation_fqns_max" json:"fulfillable_obligation_fqns_max" default:"50"`
	MultiResourceRequestMax      int `mapstructure:"multi_resource_request_max" json:"multi_resource_request_max" default:"1000"`
	BulkDecisionRequestMax       int `mapstructure:"bulk_decision_request_max" json:"bulk_decision_request_max" default:"200"`
}

func (c RequestLimitsConfig) Validate() error {
	if c.ResourceAttributeValuesMax < 1 {
		return fmt.Errorf("authorization request limit resource_attribute_values_max [%d] must be greater than 0", c.ResourceAttributeValuesMax)
	}
	if c.EntityChainEntitiesMax < 1 {
		return fmt.Errorf("authorization request limit entity_chain_entities_max [%d] must be greater than 0", c.EntityChainEntitiesMax)
	}
	if c.FulfillableObligationFqnsMax < 0 {
		return fmt.Errorf("authorization request limit fulfillable_obligation_fqns_max [%d] must be greater than or equal to 0", c.FulfillableObligationFqnsMax)
	}
	if c.MultiResourceRequestMax < 1 {
		return fmt.Errorf("authorization request limit multi_resource_request_max [%d] must be greater than 0", c.MultiResourceRequestMax)
	}
	if c.BulkDecisionRequestMax < 1 {
		return fmt.Errorf("authorization request limit bulk_decision_request_max [%d] must be greater than 0", c.BulkDecisionRequestMax)
	}
	return nil
}

type Config struct {
	Cache         EntitlementPolicyCacheConfig `mapstructure:"entitlement_policy_cache" json:"entitlement_policy_cache"`
	RequestLimits RequestLimitsConfig          `mapstructure:"request_limits" json:"request_limits"`

	// experimental features

	// enable entity direct entitlements that do not require subject mappings
	AllowDirectEntitlements bool `mapstructure:"allow_direct_entitlements" json:"allow_direct_entitlements" default:"false"`

	// enforce strict namespaced entitlement evaluation behavior in access decisioning
	EnforceNamespacedEntitlements bool `mapstructure:"enforce_namespaced_entitlements" json:"enforce_namespaced_entitlements" default:"false"`
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
	if err := c.RequestLimits.Validate(); err != nil {
		return fmt.Errorf("invalid authorization request limits config: %w", err)
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
		slog.Any("request_limits",
			slog.GroupValue(
				slog.Int("resource_attribute_values_max", c.RequestLimits.ResourceAttributeValuesMax),
				slog.Int("entity_chain_entities_max", c.RequestLimits.EntityChainEntitiesMax),
				slog.Int("fulfillable_obligation_fqns_max", c.RequestLimits.FulfillableObligationFqnsMax),
				slog.Int("multi_resource_request_max", c.RequestLimits.MultiResourceRequestMax),
				slog.Int("bulk_decision_request_max", c.RequestLimits.BulkDecisionRequestMax),
			),
		),
		slog.Bool("allow_direct_entitlements", c.AllowDirectEntitlements),
		slog.Bool("enforce_namespaced_entitlements", c.EnforceNamespacedEntitlements),
	)
}
