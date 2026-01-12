package auth

import (
	"errors"
	"time"

	"github.com/casbin/casbin/v2/persist"
	"github.com/opentdf/platform/service/logger"
	"gorm.io/gorm"
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled" default:"true"`
	PublicRoutes []string `mapstructure:"-" json:"-"`
	// Used for re-authentication of IPC connections
	IPCReauthRoutes []string `mapstructure:"-" json:"-"`
	AuthNConfig     `mapstructure:",squash"`
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

type PolicyConfig struct {
	Builtin string `mapstructure:"-" json:"-"`
	// Engine specifies the authorization engine to use.
	// - "casbin" (default): Casbin policy engine
	// - "cedar": AWS Cedar policy engine (future)
	// - "opa": Open Policy Agent engine (future)
	Engine string `mapstructure:"engine" json:"engine" default:"casbin"`
	// Version specifies the engine-specific authorization model version.
	// For Casbin:
	// - "v1" (default): Legacy path-based authorization (subject, resource, action)
	// - "v2": RPC + dimensions authorization (subject, rpc, dimensions)
	// v2 enables fine-grained resource-level authorization using AuthzResolvers.
	Version string `mapstructure:"version" json:"version" default:"v1"`
	// Username claim to use for user information
	UserNameClaim string `mapstructure:"username_claim" json:"username_claim" default:"preferred_username"`
	// Claim to use for group/role information
	GroupsClaim string `mapstructure:"groups_claim" json:"groups_claim" default:"realm_access.roles"`
	// Claim to use to reference idP clientID
	ClientIDClaim string `mapstructure:"client_id_claim" json:"client_id_claim" default:"azp"`
	// Deprecated: Use GroupsClaim instead
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
	// GormDB is the GORM database connection for SQL-backed policy storage (v2 only).
	// When provided with version: v2, policies are stored in PostgreSQL instead of CSV.
	// If nil, the CSV adapter is used.
	GormDB *gorm.DB `mapstructure:"-" json:"-"`
	// Schema is the database schema for the casbin_rule table (v2 only).
	// If empty, uses the database's default schema (search_path).
	Schema string `mapstructure:"-" json:"-"`
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
