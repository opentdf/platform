package auth

import (
	"errors"
	"time"

	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

type (
	PolicyConfig        = internalauthz.PolicyConfig
	RolesProviderConfig = internalauthz.RolesProviderConfig
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled" default:"true"`
	PublicRoutes []string `mapstructure:"-" json:"-"`
	// Used for re-authentication of IPC connections
	IPCReauthRoutes []string `mapstructure:"-" json:"-"`
	AuthNConfig     `mapstructure:",squash"`

	// Programmatic role provider overrides (not loaded from config)
	RoleProvider          authz.RoleProvider                   `mapstructure:"-" json:"-"`
	RoleProviderFactories map[string]authz.RoleProviderFactory `mapstructure:"-" json:"-"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct { //nolint:revive // AuthNConfig is a valid name
	EnforceDPoP  bool          `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	Issuer       string        `mapstructure:"issuer" json:"issuer"`
	Audience     string        `mapstructure:"audience" json:"audience"`
	Policy       PolicyConfig  `mapstructure:"policy" json:"policy"`
	CacheRefresh string        `mapstructure:"cache_refresh_interval" json:"cache_refresh_interval"`
	DPoPSkew     time.Duration `mapstructure:"dpopskew" json:"dpopskew" default:"1h"`
	TokenSkew    time.Duration `mapstructure:"skew" json:"skew" default:"1m"`
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

	return nil
}
