package auth

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled" default:"true"`
	PublicRoutes []string `mapstructure:"-" json:"-"`
	// Used for re-authentication of IPC connections
	IPCReauthRoutes []string `mapstructure:"-" json:"-"`
	AuthNConfig     `mapstructure:",squash"`

	// Programmatic role provider overrides (not loaded from config)
	RoleProvider          platformauthz.RoleProvider                   `mapstructure:"-" json:"-"`
	RoleProviderFactories map[string]platformauthz.RoleProviderFactory `mapstructure:"-" json:"-"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct { //nolint:revive // AuthNConfig is a valid name
	// Deprecated: use DPoP.Enforce (server.auth.dpop.enforce) instead. Still honored
	// during the migration window: DPoP is enforced when either field is true.
	EnforceDPoP  bool                       `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	Issuer       string                     `mapstructure:"issuer" json:"issuer"`
	Audience     string                     `mapstructure:"audience" json:"audience"`
	Policy       internalauthz.PolicyConfig `mapstructure:"policy" json:"policy"`
	CacheRefresh string                     `mapstructure:"cache_refresh_interval" json:"cache_refresh_interval"`
	DPoPSkew     time.Duration              `mapstructure:"dpopskew" json:"dpopskew" default:"1h"`
	TokenSkew    time.Duration              `mapstructure:"skew" json:"skew" default:"1m"`
	DPoP         DPoPConfig                 `mapstructure:"dpop" json:"dpop"`
}

// dpopEnforced reports whether DPoP-bound tokens are required. Enforcement is on
// when either the new DPoP.Enforce field or the deprecated EnforceDPoP field is set.
func (c AuthNConfig) dpopEnforced() bool {
	return c.DPoP.Enforce || c.EnforceDPoP // honor deprecated EnforceDPoP during migration
}

// dpopFutureIATSkew is how far ahead of server time a DPoP proof's `iat` may be
// and still be accepted, so clients whose clocks run slightly fast are not
// rejected (RFC 9449 §11.1). It reuses the access-token clock skew
// (server.auth.skew); a negative value is treated as zero.
func (c AuthNConfig) dpopFutureIATSkew() time.Duration {
	return max(c.TokenSkew, 0)
}

// dpopReplayTTL is how long a DPoP proof's `jti` must be remembered to reject
// replays. A proof is accepted while its `iat` is at most dpopFutureIATSkew
// ahead of server time and no older than DPoPSkew, so a proof first seen at t
// stays acceptable until t + dpopFutureIATSkew + DPoPSkew. The extra second
// covers the inclusive boundary of the `iat` age check.
func (c AuthNConfig) dpopReplayTTL() time.Duration {
	window := c.DPoPSkew
	if window <= 0 {
		window = time.Hour
	}
	return window + c.dpopFutureIATSkew() + time.Second
}

type DPoPConfig struct {
	// Enforce requires access tokens to be DPoP-bound. Replaces the deprecated
	// top-level server.auth.enforceDPoP field.
	Enforce         bool          `mapstructure:"enforce" json:"enforce" default:"false"`
	RequireNonce    bool          `mapstructure:"require_nonce" json:"require_nonce" default:"false"`
	NonceExpiration time.Duration `mapstructure:"nonce_expiration" json:"nonce_expiration" default:"5m"`
	// StrictHTU requires the htu claim in DPoP JWTs to include the origin
	// (scheme + host). When false (default), a path-only htu is accepted as
	// long as the path matches, easing SDK skew during rollout.
	StrictHTU bool `mapstructure:"strict_htu" json:"strict_htu" default:"false"`
	// TrustedOrigins lists the public origins (scheme://host[:port]) that
	// clients use to reach this server. When set, the origin of a full-URL htu
	// must be one of them and the request's Host is not consulted. When empty,
	// the expected origin is taken from the request's Host and TLS state.
	TrustedOrigins []string `mapstructure:"trusted_origins" json:"trusted_origins"`
}

func (c DPoPConfig) Validate() error {
	if c.RequireNonce && c.NonceExpiration <= 0 {
		return errors.New("auth.dpop.nonce_expiration must be positive when require_nonce is true")
	}
	if _, err := c.normalizedTrustedOrigins(); err != nil {
		return err
	}
	return nil
}

// normalizedTrustedOrigins validates TrustedOrigins and returns each as a
// normalized scheme://host[:port] origin, matching the normalization applied to
// received htu values. Surrounding whitespace and empty entries are ignored.
func (c DPoPConfig) normalizedTrustedOrigins() ([]string, error) {
	var origins []string
	for _, raw := range c.TrustedOrigins {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("auth.dpop.trusted_origins: invalid origin %q: %w", raw, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != httpScheme && scheme != httpsScheme {
			return nil, fmt.Errorf("auth.dpop.trusted_origins: origin %q must use the http or https scheme", raw)
		}
		if u.Host == "" || u.Hostname() == "" {
			return nil, fmt.Errorf("auth.dpop.trusted_origins: origin %q must include a host", raw)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, fmt.Errorf("auth.dpop.trusted_origins: origin %q must be scheme://host[:port] with no path, query, fragment, or user info", raw)
		}
		origin := originFromHost(u.Host, scheme == httpsScheme)
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}
	return origins, nil
}

func (c AuthNConfig) validateAuthNConfig(logger *logger.Logger) error {
	if c.Issuer == "" {
		return errors.New("config Auth.Issuer is required")
	}

	if c.Audience == "" {
		return errors.New("config Auth.Audience is required")
	}

	if c.EnforceDPoP {
		logger.Warn("config server.auth.enforceDPoP is deprecated; use server.auth.dpop.enforce instead")
	}

	if !c.dpopEnforced() {
		logger.Warn("DPoP is not enforced; set server.auth.dpop.enforce: true to require DPoP-bound tokens")
	}

	if err := c.DPoP.Validate(); err != nil {
		return err
	}

	if origins, _ := c.DPoP.normalizedTrustedOrigins(); c.DPoP.StrictHTU && len(origins) == 0 {
		logger.Warn("config server.auth.dpop.strict_htu is set without server.auth.dpop.trusted_origins; " +
			"the expected DPoP htu origin is taken from each request's Origin or Host header. " +
			"Set server.auth.dpop.trusted_origins to the server's public origins")
	}

	return nil
}
