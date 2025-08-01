package sql

import (
	"time"
)

// SQLConfig defines configuration for SQL database providers
type SQLConfig struct {
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

// DefaultSQLConfig returns a default SQL configuration
func DefaultSQLConfig() SQLConfig {
	return SQLConfig{
		Driver:             "postgres",
		Port:               5432,
		SSLMode:            "require",
		MaxOpenConnections: 25,
		MaxIdleConnections: 5,
		ConnMaxLifetime:    time.Hour,
		ConnMaxIdleTime:    time.Minute * 30,
		QueryTimeout:       time.Second * 30,
		HealthCheckQuery:   "SELECT 1",
		HealthCheckTime:    time.Second * 5,
	}
}
