package auth

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/casbin/casbin/v2/persist"
	"github.com/opentdf/platform/service/logger"
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

// GroupsClaimList is a custom type to support unmarshalling from string or []string
// for backward compatibility in config files.
type GroupsClaimList []string

func (g *GroupsClaimList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*g = GroupsClaimList{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*g = GroupsClaimList(multi)
		return nil
	}
	return errors.New("invalid groups_claim: must be string or array of strings")
}

func (g *GroupsClaimList) UnmarshalText(text []byte) error {
	s := string(text)
	// Try parsing as JSON array first (e.g., '["claim1","claim2"]' from env var)
	var multi []string
	if err := json.Unmarshal([]byte(s), &multi); err == nil {
		*g = GroupsClaimList(multi)
		return nil
	}
	// Fallback: treat as single string value
	*g = GroupsClaimList{s}
	return nil
}

type PolicyConfig struct {
	Builtin string `mapstructure:"-" json:"-"`
	// Username claim to use for user information
	UserNameClaim string `mapstructure:"username_claim" json:"username_claim" default:"preferred_username"`
	// Claims to use for group/role information (supports multiple claims)
	GroupsClaim GroupsClaimList `mapstructure:"groups_claim" json:"groups_claim" default:"[\"realm_access.roles\"]"`
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
