package sql

import (
	"time"
)

const (
	// Default SQL configuration values
	defaultPostgreSQLPort     = 5432
	defaultMaxOpenConnections = 25
	defaultMaxIdleConnections = 5
	defaultIdleTimeMinutes    = 30
	defaultTimeoutSeconds     = 30
	defaultHealthSeconds      = 5
)

// SQLConfig defines configuration for SQL database providers
type Config struct {
	// Database connection configuration
	Driver   string `mapstructure:"driver"` // "postgres", "mysql", "sqlite"
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`

	// Connection pool settings
	MaxOpenConnections int           `mapstructure:"max_open_connections"`
	MaxIdleConnections int           `mapstructure:"max_idle_connections"`
	ConnMaxLifetime    time.Duration `mapstructure:"connection_max_lifetime"`
	ConnMaxIdleTime    time.Duration `mapstructure:"connection_max_idle_time"`

	// Query settings
	QueryTimeout time.Duration `mapstructure:"query_timeout"`

	// Health check settings
	HealthCheckQuery string        `mapstructure:"health_check_query"`
	HealthCheckTime  time.Duration `mapstructure:"health_check_timeout"`

	// Description for this SQL provider instance
	Description string `mapstructure:"description"`
}

// DefaultConfig returns a default SQL configuration
func DefaultConfig() Config {
	return Config{
		Driver:             "postgres",
		Port:               defaultPostgreSQLPort,
		SSLMode:            "require",
		MaxOpenConnections: defaultMaxOpenConnections,
		MaxIdleConnections: defaultMaxIdleConnections,
		ConnMaxLifetime:    time.Hour,
		ConnMaxIdleTime:    time.Minute * defaultIdleTimeMinutes,
		QueryTimeout:       time.Second * defaultTimeoutSeconds,
		HealthCheckQuery:   "SELECT 1",
		HealthCheckTime:    time.Second * defaultHealthSeconds,
	}
}
