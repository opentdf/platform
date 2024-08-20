package auth

import (
	"fmt"
	"time"

	"github.com/opentdf/platform/service/logger"
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled" default:"true" `
	PublicRoutes []string `mapstructure:"-"`
	AuthNConfig  `mapstructure:",squash"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct { //nolint:revive // AuthNConfig is a valid name
	EnforceDPoP    bool          `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	Issuer         string        `mapstructure:"issuer" json:"issuer"`
	Audience       string        `mapstructure:"audience" json:"audience"`
	Policy         PolicyConfig  `mapstructure:"policy" json:"policy"`
	CacheRefresh   string        `mapstructure:"cache_refresh_interval"`
	DPoPSkew       time.Duration `mapstructure:"dpopskew" default:"1h"`
	TokenSkew      time.Duration `mapstructure:"skew" default:"1m"`
	PublicClientID string        `mapstructure:"public_client_id" json:"public_client_id,omitempty"`
}

type PolicyConfig struct {
	Default   string            `mapstructure:"default" json:"default"`
	RoleClaim string            `mapstructure:"claim" json:"claim"`
	RoleMap   map[string]string `mapstructure:"map" json:"map"`
	Csv       string            `mapstructure:"csv" json:"csv"`
	Model     string            `mapstructure:"model" json:"model"`
}

func (c AuthNConfig) validateAuthNConfig(logger *logger.Logger) error {
	if c.Issuer == "" {
		return fmt.Errorf("config Auth.Issuer is required")
	}

	if c.Audience == "" {
		return fmt.Errorf("config Auth.Audience is required")
	}

	if c.PublicClientID == "" {
		logger.Warn("config Auth.PublicClientID is empty and is required for discovery via well-known configuration.")
	}

	if !c.EnforceDPoP {
		logger.Warn("config Auth.EnforceDPoP is false. DPoP will not be enforced.")
	}

	return nil
}
