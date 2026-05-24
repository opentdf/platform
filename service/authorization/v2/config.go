package authorization

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// algorithmES256 is the only COSE signing algorithm the CWT verifier supports
// today; authnz-rs and other CWT issuers in the OpenTDF ecosystem use ES256
// (P-256 ECDSA).
const algorithmES256 = "ES256"

// defaultCWTCacheTTL is the fallback duration used when the operator-supplied
// rar.cwt_verifier.cache_ttl is missing or unparseable.
const defaultCWTCacheTTL = 10 * time.Minute

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

	// CWTVerifier opts the endpoint into accepting RFC 8392 CWT subject
	// tokens (subject_token_type=urn:ietf:params:oauth:token-type:cwt) in
	// addition to the JWT-family URNs the platform verifier already
	// accepts. Disabled by default.
	CWTVerifier CWTVerifierConfig `mapstructure:"cwt_verifier" json:"cwt_verifier"`
}

// CWTVerifierConfig configures the CWT subject-token verifier. When
// `enabled`, the RAR endpoint will fetch the COSE Key Set from
// `cose_keys_url` (a `/.well-known/cose-keys` endpoint published by the IdP
// minting the CWTs), verify incoming COSE_Sign1 subject tokens with it,
// and check the standard `iss` / `aud` / `exp` claims.
type CWTVerifierConfig struct {
	Enabled     bool   `mapstructure:"enabled" json:"enabled" default:"false"`
	COSEKeysURL string `mapstructure:"cose_keys_url" json:"cose_keys_url"`
	Issuer      string `mapstructure:"issuer" json:"issuer"`
	Audience    string `mapstructure:"audience" json:"audience"`
	// Algorithm is the COSE algorithm label of the IdP's signing key.
	// Today only ES256 is supported (the algorithm authnz-rs uses).
	Algorithm string `mapstructure:"algorithm" json:"algorithm" default:"ES256"`
	// CacheTTL is how long the verifier caches the fetched COSE Key Set
	// before refreshing. Tune to match the IdP's Cache-Control.
	CacheTTL string `mapstructure:"cache_ttl" json:"cache_ttl" default:"10m"`
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

	return validateCWTVerifier(&c.RAR.CWTVerifier)
}

func validateCWTVerifier(c *CWTVerifierConfig) error {
	if !c.Enabled {
		return nil
	}
	if c.COSEKeysURL == "" {
		return errors.New("rar.cwt_verifier.enabled is true but cose_keys_url is empty")
	}
	if c.Issuer == "" {
		return errors.New("rar.cwt_verifier.enabled is true but issuer is empty")
	}
	if c.Audience == "" {
		return errors.New("rar.cwt_verifier.enabled is true but audience is empty")
	}
	if c.Algorithm == "" {
		c.Algorithm = algorithmES256
	}
	if c.Algorithm != algorithmES256 {
		return fmt.Errorf("rar.cwt_verifier.algorithm %q not supported (only ES256 today)", c.Algorithm)
	}
	if c.CacheTTL == "" {
		c.CacheTTL = "10m"
	}
	if _, err := time.ParseDuration(c.CacheTTL); err != nil {
		return fmt.Errorf("rar.cwt_verifier.cache_ttl invalid: %w", err)
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
				slog.Any("cwt_verifier",
					slog.GroupValue(
						slog.Bool("enabled", c.RAR.CWTVerifier.Enabled),
						slog.String("cose_keys_url", c.RAR.CWTVerifier.COSEKeysURL),
						slog.String("issuer", c.RAR.CWTVerifier.Issuer),
						slog.String("audience", c.RAR.CWTVerifier.Audience),
						slog.String("algorithm", c.RAR.CWTVerifier.Algorithm),
						slog.String("cache_ttl", c.RAR.CWTVerifier.CacheTTL),
					),
				),
			),
		),
		slog.Bool("allow_direct_entitlements", c.AllowDirectEntitlements),
		slog.Bool("enforce_namespaced_entitlements", c.EnforceNamespacedEntitlements),
	)
}
