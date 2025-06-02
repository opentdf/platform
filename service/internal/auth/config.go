package auth

import (
	"encoding/json"
	"errors"
	"os"
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
	EnforceDPoP    bool          `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	EnrichUserInfo bool          `mapstructure:"enrichUserInfo" json:"enrichUserInfo" default:"false"`
	TLSNoVerify    bool          `mapstructure:"tls_no_verify" json:"tls_no_verify" default:"false"`
	Issuer         string        `mapstructure:"issuer" json:"issuer"`
	Audience       string        `mapstructure:"audience" json:"audience"`
	Policy         PolicyConfig  `mapstructure:"policy" json:"policy"`
	CacheRefresh   string        `mapstructure:"cache_refresh_interval"`
	DPoPSkew       time.Duration `mapstructure:"dpopskew" default:"1h"`
	TokenSkew      time.Duration `mapstructure:"skew" default:"1m"`
	PublicClientID string        `mapstructure:"public_client_id" json:"public_client_id,omitempty"`

	// Client credentials for the server to support Token Exchange
	ClientID string `mapstructure:"clientId" json:"clientId"`
	// Path to the PEM file containing the OIDC client private key (for private_key_jwt)
	ClientPrivateKeyPath string `mapstructure:"clientPrivateKeyPath" json:"clientPrivateKeyPath"`
	// Inline PEM for the OIDC client private key (optional, for private_key_jwt)
	ClientPrivateKey string `mapstructure:"clientPrivateKey" json:"clientPrivateKey"`
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
	return g.UnmarshalJSON(text)
}

type PolicyConfig struct {
	Builtin string `mapstructure:"-" json:"-"`
	// Username claim to use for user information
	UserNameClaim string `mapstructure:"username_claim" json:"username_claim" default:"preferred_username"`
	// Claims to use for group/role information (now supports multiple claims)
	GroupsClaim GroupsClaimList `mapstructure:"groups_claim" json:"group_claim" default:"[\"realm_access.roles\"]"`
	// Deprecated: Use GroupClaim instead
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

var (
	errIssuerRequired     = errors.New("config Auth.Issuer is required")
	errAudienceRequired   = errors.New("config Auth.Audience is required")
	errClientIDRequired   = errors.New("config Auth.ClientID is required for token exchange to fetch userinfo")
	errPrivateKeyRequired = errors.New("config Auth.ClientPrivateKey or ClientPrivateKeyPath is required for private_key_jwt")
	errMutuallyExclusive  = errors.New("config Auth.clientPrivateKey and clientPrivateKeyPath are mutually exclusive; please provide only one")
)

// readConfigFile allows injection for testing
var readConfigFile = os.ReadFile

func (c AuthNConfig) validateAuthNConfig(logger *logger.Logger) error {
	if c.PublicClientID == "" {
		logger.Warn("config Auth.PublicClientID is empty and is required for discovery via well-known configuration.")
	}

	if !c.EnforceDPoP {
		logger.Warn("config Auth.EnforceDPoP is false. DPoP will not be enforced.")
	}

	if c.EnrichUserInfo {
		if c.Issuer == "" {
			return errIssuerRequired
		}
		if c.Audience == "" {
			return errAudienceRequired
		}
		if c.ClientID == "" {
			return errClientIDRequired
		}
		if c.ClientPrivateKey == "" && c.ClientPrivateKeyPath == "" {
			return errPrivateKeyRequired
		} else if c.ClientPrivateKey != "" && c.ClientPrivateKeyPath != "" {
			return errMutuallyExclusive
		}
		// Read in the private key if provided as a path and save it to ClientPrivateKey
		if c.ClientPrivateKeyPath != "" {
			privateKeyBytes, err := readConfigFile(c.ClientPrivateKeyPath)
			if err != nil {
				return errors.New("failed to read client private key from path: " + c.ClientPrivateKeyPath + ": " + err.Error())
			}
			c.ClientPrivateKey = string(privateKeyBytes)
		}
	} else {
		logger.Warn("config Auth.EnrichUserInfo is false. UserInfo enrichment is disabled and token exchange will be skipped.")
	}

	return nil
}
