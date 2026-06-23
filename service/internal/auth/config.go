package auth

import (
	"errors"
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
	EnforceDPoP  bool                       `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	Issuer       string                     `mapstructure:"issuer" json:"issuer"`
	Audience     string                     `mapstructure:"audience" json:"audience"`
	Policy       internalauthz.PolicyConfig `mapstructure:"policy" json:"policy"`
	CacheRefresh string                     `mapstructure:"cache_refresh_interval" json:"cache_refresh_interval"`
	DPoPSkew     time.Duration              `mapstructure:"dpopskew" json:"dpopskew" default:"1h"`
	TokenSkew    time.Duration              `mapstructure:"skew" json:"skew" default:"1m"`
	DPoP         DPoPConfig                 `mapstructure:"dpop" json:"dpop"`
}

type DPoPConfig struct {
	RequireNonce    bool          `mapstructure:"require_nonce" json:"require_nonce" default:"false"`
	NonceExpiration time.Duration `mapstructure:"nonce_expiration" json:"nonce_expiration" default:"5m"`
	// StrictHTU requires the htu claim in DPoP JWTs to include the origin
	// (scheme + host). When false (default), a path-only htu is accepted as
	// long as the path matches, easing SDK skew during rollout.
	StrictHTU bool `mapstructure:"strict_htu" json:"strict_htu" default:"false"`
}

func (c DPoPConfig) Validate() error {
	if c.RequireNonce && c.NonceExpiration <= 0 {
		return errors.New("auth.dpop.nonce_expiration must be positive when require_nonce is true")
	}
	return nil
}

func (c AuthNConfig) validateAuthNConfig(logger *logger.Logger) error {
	if c.Issuer == "" {
		return errors.New("config Auth.Issuer is required")
	}

	if c.Audience == "" {
		return errors.New("config Auth.Audience is required")
	}

	if !c.EnforceDPoP {
		logger.Warn("config Auth.EnforceDPoP is false. DPoP will not be enforced.")
	}

	if err := c.DPoP.Validate(); err != nil {
		return err
	}

	return nil
}
