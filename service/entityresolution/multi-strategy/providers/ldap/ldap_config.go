package ldap

import (
	"time"
)

const (
	// Default LDAP configuration values
	defaultLDAPPort       = 389
	defaultTimeoutSeconds = 30
	defaultMaxConnections = 10
	defaultIdleMinutes    = 10
	defaultConnectSeconds = 10
	defaultHealthSeconds  = 5
)

// LDAPConfig defines configuration for LDAP directory providers
type Config struct {
	// Connection settings
	Host       string        `mapstructure:"host"`
	Port       int           `mapstructure:"port"`
	UseTLS     bool          `mapstructure:"use_tls"`
	SkipVerify bool          `mapstructure:"skip_verify"`
	Timeout    time.Duration `mapstructure:"timeout"`

	// Authentication
	BindDN       string `mapstructure:"bind_dn"`
	BindPassword string `mapstructure:"bind_password"`

	// Connection pool settings
	MaxConnections int           `mapstructure:"max_connections"`
	IdleTimeout    time.Duration `mapstructure:"idle_timeout"`
	ConnectTimeout time.Duration `mapstructure:"connect_timeout"`
	RequestTimeout time.Duration `mapstructure:"request_timeout"`

	// Health check settings
	HealthCheckBindTest bool          `mapstructure:"health_check_bind_test"`
	HealthCheckTimeout  time.Duration `mapstructure:"health_check_timeout"`

	// Description for this LDAP provider instance
	Description string `mapstructure:"description"`
}

// DefaultConfig returns a default LDAP configuration
func DefaultConfig() Config {
	return Config{
		Port:                defaultLDAPPort,
		UseTLS:              true,
		SkipVerify:          false,
		Timeout:             time.Second * defaultTimeoutSeconds,
		MaxConnections:      defaultMaxConnections,
		IdleTimeout:         time.Minute * defaultIdleMinutes,
		ConnectTimeout:      time.Second * defaultConnectSeconds,
		RequestTimeout:      time.Second * defaultTimeoutSeconds,
		HealthCheckBindTest: true,
		HealthCheckTimeout:  time.Second * defaultHealthSeconds,
	}
}
