package config

import (
	"context"
	"errors"
	"log/slog"

	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/tracing"
)

type ConfigChangeHook func(ConfigServices) error
type ConfigWatcher func(ConfigChangeHook)
type ConfigServices map[string]ServiceConfig
type ServiceConfig map[string]any

// Config represents the configuration settings for the service.
type Config struct {
	// DevMode specifies whether the service is running in development mode.
	DevMode bool `mapstructure:"dev_mode" json:"dev_mode"`

	// DB represents the configuration settings for the database.
	DB db.Config `mapstructure:"db" json:"db"`

	// Server represents the configuration settings for the server.
	Server server.Config `mapstructure:"server" json:"server"`

	// Logger represents the configuration settings for the logger.
	Logger logger.Config `mapstructure:"logger" json:"logger"`

	// Mode specifies which services to run.
	// By default, it runs all services.
	Mode []string `mapstructure:"mode" json:"mode" default:"[\"all\"]"`

	// SDKConfig represents the configuration settings for the SDK.
	SDKConfig SDKConfig `mapstructure:"sdk_config" json:"sdk_config"`

	// Services represents the configuration settings for the services.
	Services ConfigServices `mapstructure:"services"`

	// Trace is for configuring open telemetry based tracing.
	Trace tracing.Config `mapstructure:"trace"`
}

// SDKConfig represents the configuration for the SDK.
type SDKConfig struct {
	// Connection to the Core Platform
	CorePlatformConnection Connection `mapstructure:"core" json:"core"`

	// Connection to an ERS if not in the core platform
	EntityResolutionConnection Connection `mapstructure:"entityresolution" json:"entityresolution"`

	// ClientID is the client ID used for client credentials grant.
	// It is required together with ClientSecret.
	ClientID string `mapstructure:"client_id" json:"client_id" validate:"required_with=ClientSecret"`

	// ClientSecret is the client secret used for client credentials grant.
	// It is required together with ClientID.
	ClientSecret string `mapstructure:"client_secret" json:"client_secret" validate:"required_with=ClientID"`
}

type Connection struct {
	// Endpoint is the URL of the platform or service.
	Endpoint string `mapstructure:"endpoint" json:"endpoint"`

	// Plaintext specifies whether the SDK should use plaintext communication.
	Plaintext bool `mapstructure:"plaintext" json:"plaintext" default:"false" validate:"boolean"`

	// Insecure specifies whether the SDK should use insecure TLS communication.
	Insecure bool `mapstructure:"insecure" json:"insecure" default:"false" validate:"boolean"`
}

var (
	ErrLoadingConfig       = errors.New("error loading config")
	ErrUnmarshallingConfig = errors.New("error unmarshalling config")
	ErrSettingConfig       = errors.New("error setting config")
)

// LogValue returns a slog.Value representation of the config.
// We exclude logging service configuration as it may contain sensitive information.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("dev_mode", c.DevMode),
		slog.Any("db", c.DB),
		slog.Any("logger", c.Logger),
		slog.Any("mode", c.Mode),
		slog.Any("sdk_config", c.SDKConfig),
		slog.Any("server", c.Server),
	)
}

func (c SDKConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Group("core",
			"endpoint", c.CorePlatformConnection.Endpoint,
			"plaintext", c.CorePlatformConnection.Plaintext,
			"insecure", c.CorePlatformConnection.Insecure),
		slog.Group("entityresolution",
			"endpoint", c.EntityResolutionConnection.Endpoint,
			"plaintext", c.EntityResolutionConnection.Plaintext,
			"insecure", c.EntityResolutionConnection.Insecure),
		slog.String("client_id", c.ClientID),
		slog.String("client_secret", "[REDACTED]"),
	)
}

// LoadConfig loads configuration using the provided loader or creates a default Viper loader
func LoadConfig(ctx context.Context, key, file string) (*Config, ConfigWatcher, error) {
	config := &Config{}

	// Create default loader if none provided
	loader, err := NewEnvironmentLoader(key, file)
	if err != nil {
		return nil, nil, err
	}

	// Load initial configuration
	if err := loader.Load(config); err != nil {
		return nil, nil, err
	}

	// Watch for changes
	onConfigChange, err := loader.Watch(ctx, config)
	if err != nil {
		return nil, nil, err
	}

	return config, onConfigChange, nil
}
