package auth

import (
	"errors"
	"time"

	"github.com/casbin/casbin/v2/persist"
	"github.com/opentdf/platform/service/logger"
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled" default:"true" `
	PublicRoutes []string `mapstructure:"-"`
	// Used for re-authentication of IPC connections
	IPCReauthRoutes []string `mapstructure:"-"`
	AuthNConfig     `mapstructure:",squash"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct { //nolint:revive // AuthNConfig is a valid name
	EnforceDPoP  bool          `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	Issuer       string        `mapstructure:"issuer" json:"issuer"`
	Audience     string        `mapstructure:"audience" json:"audience"`
	Policy       PolicyConfig  `mapstructure:"policy" json:"policy"`
	CacheRefresh string        `mapstructure:"cacheRefreshInterval" json:"cacheRefreshInterval" default:"15m"`
	DPoPSkew     time.Duration `mapstructure:"dpopskew" json:"dpopskew" default:"1h"`
	TokenSkew    time.Duration `mapstructure:"skew" default:"1m"`
}

type PolicyConfig struct {
	Builtin string `mapstructure:"-" json:"-"`
	// Username claim to use for user information
	UserNameClaim string `mapstructure:"username_claim" json:"username_claim" default:"preferred_username"`
	// Claim to use for group/role information
	GroupsClaim string `mapstructure:"groups_claim" json:"group_claim" default:"realm_access.roles"`
	// Deprecated: Use GroupClain instead
	RoleClaim string `mapstructure:"claim" json:"claim" default:"realm_access.roles"`
	// Deprecated: Use Casbin grouping statements g, <user/group>, <role>
	RoleMap map[string]string `mapstructure:"map" json:"map"`
	// Override the builtin policy with a custom policy
	Csv string `mapstructure:"csv" json:"csv"`
	// Extend the builtin policy with a custom policy
	Extension string `mapstructure:"extension" json:"extension"`
	Model     string `mapstructure:"model" json:"model"`
	// Override the default string-adapter
	Adapter persist.Adapter `mapstructure:"-" json:"-"`
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
