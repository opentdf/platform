package authorization

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var ErrInvalidRequestLimitConfig = errors.New("invalid request limit configuration")

// Manage config for EntitlementPolicyCache: attributes, subject mappings, and registered resources
// Default: caching disabled, and if enabled, refresh interval defaulted to 30 seconds.
type EntitlementPolicyCacheConfig struct {
	Enabled         bool   `mapstructure:"enabled" json:"enabled" default:"false"`
	RefreshInterval string `mapstructure:"refresh_interval" json:"refresh_interval" default:"30s"`
}

type RequestLimitsConfig struct {
	ResourceAttributeValuesFqnsMax              int `mapstructure:"resource_attribute_values_fqns_max" json:"resource_attribute_values_fqns_max" default:"20"`
	EntityIdentifierEntityChainEntitiesMax      int `mapstructure:"entity_identifier_entity_chain_entities_max" json:"entity_identifier_entity_chain_entities_max" default:"10"`
	DecisionRequestFulfillableObligationFqnsMax int `mapstructure:"decision_request_fulfillable_obligation_fqns_max" json:"decision_request_fulfillable_obligation_fqns_max" default:"50"`
	GetDecisionMultiResourceResourcesMax        int `mapstructure:"get_decision_multi_resource_resources_max" json:"get_decision_multi_resource_resources_max" default:"1000"`
	GetDecisionBulkDecisionRequestsMax          int `mapstructure:"get_decision_bulk_decision_requests_max" json:"get_decision_bulk_decision_requests_max" default:"200"`
}

func (c RequestLimitsConfig) Validate() error {
	if c.ResourceAttributeValuesFqnsMax < 1 {
		return requestLimitConfigError("resource_attribute_values_fqns_max", c.ResourceAttributeValuesFqnsMax)
	}
	if c.EntityIdentifierEntityChainEntitiesMax < 1 {
		return requestLimitConfigError("entity_identifier_entity_chain_entities_max", c.EntityIdentifierEntityChainEntitiesMax)
	}
	if c.DecisionRequestFulfillableObligationFqnsMax < 1 {
		return requestLimitConfigError("decision_request_fulfillable_obligation_fqns_max", c.DecisionRequestFulfillableObligationFqnsMax)
	}
	if c.GetDecisionMultiResourceResourcesMax < 1 {
		return requestLimitConfigError("get_decision_multi_resource_resources_max", c.GetDecisionMultiResourceResourcesMax)
	}
	if c.GetDecisionBulkDecisionRequestsMax < 1 {
		return requestLimitConfigError("get_decision_bulk_decision_requests_max", c.GetDecisionBulkDecisionRequestsMax)
	}
	return nil
}

func requestLimitConfigError(name string, value int) error {
	return fmt.Errorf("%s [%d] must be greater than 0: %w", name, value, ErrInvalidRequestLimitConfig)
}

type Config struct {
<<<<<<< HEAD
	Cache EntitlementPolicyCacheConfig `mapstructure:"entitlement_policy_cache" json:"entitlement_policy_cache"`
=======
	Cache         EntitlementPolicyCacheConfig `mapstructure:"entitlement_policy_cache" json:"entitlement_policy_cache"`
	RequestLimits RequestLimitsConfig          `mapstructure:"request_limits" json:"request_limits"`

	// experimental features

	// enable entity direct entitlements that do not require subject mappings
	AllowDirectEntitlements bool `mapstructure:"allow_direct_entitlements" json:"allow_direct_entitlements" default:"false"`

	// enforce strict namespaced entitlement evaluation behavior in access decisioning
	EnforceNamespacedEntitlements bool `mapstructure:"enforce_namespaced_entitlements" json:"enforce_namespaced_entitlements" default:"false"`
>>>>>>> 9d16f80 (feat(authz): make v2 request limits configurable (#3508))
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
<<<<<<< HEAD
=======
		slog.Any("request_limits",
			slog.GroupValue(
				slog.Int("resource_attribute_values_fqns_max", c.RequestLimits.ResourceAttributeValuesFqnsMax),
				slog.Int("entity_identifier_entity_chain_entities_max", c.RequestLimits.EntityIdentifierEntityChainEntitiesMax),
				slog.Int("decision_request_fulfillable_obligation_fqns_max", c.RequestLimits.DecisionRequestFulfillableObligationFqnsMax),
				slog.Int("get_decision_multi_resource_resources_max", c.RequestLimits.GetDecisionMultiResourceResourcesMax),
				slog.Int("get_decision_bulk_decision_requests_max", c.RequestLimits.GetDecisionBulkDecisionRequestsMax),
			),
		),
		slog.Bool("allow_direct_entitlements", c.AllowDirectEntitlements),
		slog.Bool("enforce_namespaced_entitlements", c.EnforceNamespacedEntitlements),
>>>>>>> 9d16f80 (feat(authz): make v2 request limits configurable (#3508))
	)
}
