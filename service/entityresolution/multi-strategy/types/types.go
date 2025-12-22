//nolint:revive,nolintlint // var-naming: package name "types" is generic but required for organizational clarity
package types

import (
	"context"
	"time"
)

// Constants for failure strategy values
const (
	FailureStrategyFailFast = "fail-fast"
	FailureStrategyContinue = "continue"
)

// Constants for entity type values
const (
	EntityTypeSubject     = "subject"
	EntityTypeEnvironment = "environment"
)

// Mapper defines the interface for mapping JWT claims to provider parameters
// and transforming provider results back to standardized claims
type Mapper interface {
	// ExtractParameters extracts parameters from JWT claims using strategy's input mapping
	ExtractParameters(jwtClaims JWTClaims, inputMapping []InputMapping) (map[string]interface{}, error)

	// TransformResults transforms provider results using strategy's output mapping
	TransformResults(rawData map[string]interface{}, outputMapping []OutputMapping) (map[string]interface{}, error)

	// ValidateInputMapping validates that input mapping is compatible with this provider type
	ValidateInputMapping(inputMapping []InputMapping) error

	// ValidateOutputMapping validates that output mapping is compatible with this provider type
	ValidateOutputMapping(outputMapping []OutputMapping) error

	// GetSupportedTransformations returns provider-specific transformations
	GetSupportedTransformations() []string
}

// Provider interface that all backend providers must implement
type Provider interface {
	// Name returns the provider instance name
	Name() string

	// Type returns the provider type (sql, ldap, claims, etc.)
	Type() string

	// ResolveEntity executes the strategy against this provider
	ResolveEntity(ctx context.Context, strategy MappingStrategy, params map[string]interface{}) (*RawResult, error)

	// HealthCheck verifies the provider is healthy
	HealthCheck(ctx context.Context) error

	// GetMapper returns the provider's mapper implementation
	GetMapper() Mapper

	// Close cleans up provider resources
	Close() error
}

// RawResult represents the raw result from a provider before output mapping
type RawResult struct {
	// Data contains the raw field data from the provider
	Data map[string]interface{}

	// Metadata contains provider-specific metadata
	Metadata map[string]interface{}
}

// EntityResult represents the final result after output mapping
type EntityResult struct {
	// OriginalID is the entity ID from the request
	OriginalID string

	// Claims contains the mapped claims (field-agnostic)
	Claims map[string]interface{}

	// Metadata contains processing metadata
	Metadata map[string]interface{}
}

// JWTClaims represents JWT claims for strategy matching
type JWTClaims map[string]interface{}

// contextKey is a private type for context keys to avoid collisions
type contextKey string

// JWTClaimsContextKey is the typed context key for JWT claims
const JWTClaimsContextKey contextKey = "jwt_claims"

// MultiStrategyConfig is the main configuration for the multi-strategy ERS
type MultiStrategyConfig struct {
	// Providers defines the available data providers
	Providers map[string]ProviderConfig `mapstructure:"providers"`

	// MappingStrategies defines the strategies for entity resolution
	MappingStrategies []MappingStrategy `mapstructure:"mapping_strategies"`

	// FailureStrategy controls how the service handles strategy failures globally
	FailureStrategy string `mapstructure:"failure_strategy"` // "fail-fast" (default) or "continue"

	// HealthCheck configuration
	HealthCheck HealthCheckConfig `mapstructure:"health_check"`
}

// ProviderConfig defines a data provider configuration
type ProviderConfig struct {
	Type       string                 `mapstructure:"type"` // "sql", "ldap", "claims"
	Connection map[string]interface{} `mapstructure:"connection"`
}

// MappingStrategy defines how to resolve entities for specific JWT contexts
type MappingStrategy struct {
	Name         string             `mapstructure:"name"`
	Provider     string             `mapstructure:"provider"`
	Conditions   StrategyConditions `mapstructure:"conditions"`
	InputMapping []InputMapping     `mapstructure:"input_mapping"`

	// Strategy behavior configuration
	EntityType string `mapstructure:"entity_type"` // "subject" or "environment"

	// Provider-specific configuration
	Query      string            `mapstructure:"query"`            // SQL query
	LDAPSearch *LDAPSearchConfig `mapstructure:"ldap_search"`      // LDAP search config
	RedisOps   *RedisOperations  `mapstructure:"redis_operations"` // Future: Redis operations

	// Field-agnostic output mapping
	OutputMapping []OutputMapping `mapstructure:"output_mapping"`
}

// StrategyConditions define when this strategy should be used
type StrategyConditions struct {
	JWTClaims []JWTClaimCondition `mapstructure:"jwt_claims"`
}

// JWTClaimCondition defines a condition on a JWT claim
type JWTClaimCondition struct {
	Claim    string   `mapstructure:"claim"`
	Operator string   `mapstructure:"operator"` // "exists", "equals", "contains", "regex"
	Values   []string `mapstructure:"values"`
}

// InputMapping defines how to extract parameters from JWT for queries
type InputMapping struct {
	JWTClaim  string `mapstructure:"jwt_claim"`
	Parameter string `mapstructure:"parameter"`
	Required  bool   `mapstructure:"required"`
	Default   string `mapstructure:"default"`
}

// OutputMapping defines how to map provider results to claims (field-agnostic)
type OutputMapping struct {
	// Source field names (provider-specific)
	SourceColumn    string `mapstructure:"source_column"`    // SQL column name
	SourceAttribute string `mapstructure:"source_attribute"` // LDAP attribute name
	SourceClaim     string `mapstructure:"source_claim"`     // JWT claim name
	SourceKey       string `mapstructure:"source_key"`       // Redis key name

	// Target claim name (field-agnostic)
	ClaimName string `mapstructure:"claim_name"`

	// Optional transformation
	Transformation string `mapstructure:"transformation"` // "array", "csv_to_array", "ldap_dn_to_cn_array", etc.
}

// LDAPSearchConfig defines LDAP search parameters
type LDAPSearchConfig struct {
	BaseDN     string   `mapstructure:"base_dn"`
	Filter     string   `mapstructure:"filter"`
	Scope      string   `mapstructure:"scope"`
	Attributes []string `mapstructure:"attributes"`
}

// RedisOperations defines Redis operations (future enhancement)
type RedisOperations struct {
	Get string `mapstructure:"get"`
	TTL string `mapstructure:"ttl"`
}

// HealthCheckConfig defines health check settings
type HealthCheckConfig struct {
	Enabled        bool                  `mapstructure:"enabled"`
	Interval       time.Duration         `mapstructure:"interval"`
	ProviderChecks []ProviderHealthCheck `mapstructure:"provider_checks"`
}

// ProviderHealthCheck defines health check for a specific provider
type ProviderHealthCheck struct {
	Provider string `mapstructure:"provider"`
	Query    string `mapstructure:"query"`     // SQL health check query
	BindTest bool   `mapstructure:"bind_test"` // LDAP bind test
	Ping     bool   `mapstructure:"ping"`      // Redis ping
}
