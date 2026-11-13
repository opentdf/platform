package auth

import (
	"errors"
	"fmt"
	"net"
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
	// Deprecated: use HTU.Strict (server.auth.dpop.htu.strict) instead. Still
	// honored: strict htu matching applies when either field is true. Unlike
	// HTU.Strict it does not require HTU.Origins, so existing deployments keep
	// starting.
	StrictHTU bool `mapstructure:"strict_htu" json:"strict_htu" default:"false"`
	// HTU configures how the htu claim of a DPoP proof is matched.
	HTU DPoPHTUConfig `mapstructure:"htu" json:"htu"`
}

// DPoPHTUConfig configures how the htu claim of a DPoP proof is matched
// (server.auth.dpop.htu).
type DPoPHTUConfig struct {
	// Strict requires the htu claim in DPoP JWTs to include the origin
	// (scheme + host); a path-only htu is rejected. When false (default), a
	// path-only htu is accepted as long as the path matches, for clients that
	// sign path-only htu values. Requires Origins; Validate fails otherwise.
	Strict bool `mapstructure:"strict" json:"strict" default:"false"`
	// Origins lists the public origins (scheme://host[:port]) that clients use
	// to reach this server. When set, the origin of a full-URL htu must be one
	// of them instead of being derived from the request's Host. When empty,
	// the request's Host is trusted, so load balancers should be configured to
	// reject (403) requests with unrecognized Host values. In-process
	// reauthorization is matched against its own Host and ignores Origins.
	Origins []string `mapstructure:"origins" json:"origins"`
}

func (c DPoPConfig) Validate() error {
	if c.RequireNonce && c.NonceExpiration <= 0 {
		return errors.New("auth.dpop.nonce_expiration must be positive when require_nonce is true")
	}
	origins, err := c.HTU.normalizedOrigins()
	if err != nil {
		return err
	}
	if c.HTU.Strict && len(origins) == 0 {
		return errors.New("server.auth.dpop.htu.origins must be set when server.auth.dpop.htu.strict is true: " +
			"list the public origins clients use to reach this server, " +
			`for example origins: ["https://platform.example.com"] ` +
			"(env OPENTDF_SERVER_AUTH_DPOP_HTU_ORIGINS=https://platform.example.com)")
	}
	return nil
}

// strictHTU reports whether only full-URL htu values are accepted, honoring
// the deprecated StrictHTU field.
func (c DPoPConfig) strictHTU() bool {
	return c.HTU.Strict || c.StrictHTU
}

// normalizedOrigins validates Origins and returns each as a normalized
// scheme://host[:port] origin, matching the normalization applied to received
// htu values. Surrounding whitespace and empty entries are ignored; they
// appear when a comma-separated environment variable has spaces or a trailing
// comma.
func (c DPoPHTUConfig) normalizedOrigins() ([]string, error) {
	const key = "server.auth.dpop.htu.origins"
	var origins []string
	for _, raw := range c.Origins {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.ContainsAny(raw, ",;") || strings.Count(raw, "://") > 1 {
			return nil, fmt.Errorf("%s: origin %q looks like several origins in one entry; "+
				"list each origin separately (a YAML list, or a comma-separated environment variable)", key, raw)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid origin %q: %w", key, raw, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != httpScheme && scheme != httpsScheme {
			return nil, fmt.Errorf("%s: origin %q must use the http or https scheme", key, raw)
		}
		if u.Host == "" || u.Hostname() == "" {
			return nil, fmt.Errorf("%s: origin %q must include a host", key, raw)
		}
		if h := u.Hostname(); net.ParseIP(h) == nil && !isOriginHostName(h) {
			return nil, fmt.Errorf("%s: origin %q has invalid host %q: wildcards are not supported, "+
				"list each origin separately", key, raw, h)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, fmt.Errorf("%s: origin %q must be scheme://host[:port] with no path, query, fragment, or user info", key, raw)
		}
		origin := originFromHost(u.Host, scheme == httpsScheme)
		// originFromHost falls back to an unnormalized value it cannot parse
		// (e.g. an IPv6 zone identifier); such an origin would never match.
		if ou, err := url.Parse(origin); err != nil || ou.Host == "" || ou.Path != "" {
			return nil, fmt.Errorf("%s: origin %q cannot be normalized to scheme://host[:port]", key, raw)
		}
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}
	return origins, nil
}

// isOriginHostName reports whether h contains only characters that can appear
// in a host name clients connect to. url.Parse also accepts sub-delimiters
// such as '*' or ',' in a host; an origin containing them would never match a
// received htu.
func isOriginHostName(h string) bool {
	return h != "" && strings.Trim(strings.ToLower(h), "abcdefghijklmnopqrstuvwxyz0123456789.-_") == ""
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

	if c.DPoP.StrictHTU {
		logger.Warn("config server.auth.dpop.strict_htu is deprecated; use server.auth.dpop.htu.strict with server.auth.dpop.htu.origins instead")
	}

	if !c.dpopEnforced() {
		logger.Warn("DPoP is not enforced; set server.auth.dpop.enforce: true to require DPoP-bound tokens")
	}

	if err := c.DPoP.Validate(); err != nil {
		return err
	}

	return nil
}
