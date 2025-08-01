package ldap

import (
	"time"
)

// LDAPConfig defines configuration for LDAP directory providers
type LDAPConfig struct {
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

// DefaultLDAPConfig returns a default LDAP configuration
func DefaultLDAPConfig() LDAPConfig {
	return LDAPConfig{
		Port:                389,
		UseTLS:              true,
		SkipVerify:          false,
		Timeout:             time.Second * 30,
		MaxConnections:      10,
		IdleTimeout:         time.Minute * 10,
		ConnectTimeout:      time.Second * 10,
		RequestTimeout:      time.Second * 30,
		HealthCheckBindTest: true,
		HealthCheckTimeout:  time.Second * 5,
	}
}
