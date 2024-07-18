package auth

import (
	"fmt"
	"time"

	"github.com/opentdf/platform/service/internal/logger"
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `yaml:"enabled" default:"true" `
	PublicRoutes []string `mapstructure:"-"`
	AuthNConfig  `mapstructure:",squash"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct { //nolint:revive // AuthNConfig is a valid name
	EnforceDPoP  bool          `yaml:"enforceDPoP" json:"enforceDPoP" mapstructure:"enforceDPoP" default:"false"`
	Issuer       string        `yaml:"issuer" json:"issuer"`
	Audience     string        `yaml:"audience" json:"audience"`
	Policy       PolicyConfig  `yaml:"policy" json:"policy" mapstructure:"policy"`
	CacheRefresh string        `mapstructure:"cache_refresh_interval"`
	DPoPSkew     time.Duration `mapstructure:"dpopskew" default:"1h"`
	TokenSkew    time.Duration `mapstructure:"skew" default:"1m"`
}

type PolicyConfig struct {
	Default   string            `yaml:"default" json:"default"`
	RoleClaim string            `yaml:"claim" json:"claim" mapstructure:"claim"`
	RoleMap   map[string]string `yaml:"map" json:"map" mapstructure:"map"`
	Csv       string            `yaml:"csv" json:"csv"`
	Model     string            `yaml:"model" json:"model"`
}

func (c AuthNConfig) validateAuthNConfig(logger *logger.Logger) error {
	if c.Issuer == "" {
		return fmt.Errorf("config Auth.Issuer is required")
	}

	if c.Audience == "" {
		return fmt.Errorf("config Auth.Audience is required")
	}

	if !c.EnforceDPoP {
		logger.Warn("config Auth.EnforceDPoP is false. DPoP will not be enforced.")
	}

	return nil
}
