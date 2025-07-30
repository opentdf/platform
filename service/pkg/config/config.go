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

// ChangeHook is a function invoked when the configuration changes.
type ChangeHook func(configServices ServicesMap) error

// Config structure holding all services.
type ServicesMap map[string]ServiceConfig

// Config structure holding a single service.
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
	Services ServicesMap `mapstructure:"services"`

	// Trace is for configuring open telemetry based tracing.
	Trace tracing.Config `mapstructure:"trace"`

	// onConfigChangeHooks is a list of functions to call when the configuration changes.
	onConfigChangeHooks []ChangeHook
	// loaders is a list of configuration loaders.
	loaders []Loader
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

// AddLoader adds a configuration loader to the list of loaders.
func (c *Config) AddLoader(loader Loader) {
	c.loaders = append(c.loaders, loader)
}

// AddOnConfigChangeHook adds a hook to the list of hooks to call when the configuration changes.
func (c *Config) AddOnConfigChangeHook(hook ChangeHook) {
	c.onConfigChangeHooks = append(c.onConfigChangeHooks, hook)
}

// Watch starts watching the configuration for changes in all config loaders.
func (c *Config) Watch(ctx context.Context) error {
	if len(c.loaders) == 0 {
		return nil
	}
	for _, loader := range c.loaders {
		if err := loader.Watch(ctx, c, c.OnChange); err != nil {
			return err
		}
	}
	return nil
}

// Close invokes close method on all config loaders.
func (c *Config) Close(ctx context.Context) error {
	if len(c.loaders) == 0 {
		return nil
	}
	slog.DebugContext(ctx, "closing config loaders")
	for _, loader := range c.loaders {
		if err := loader.Close(); err != nil {
			return err
		}
	}
	return nil
}

// OnChange invokes all registered onConfigChangeHooks after a configuration change.
func (c *Config) OnChange(_ context.Context) error {
	if len(c.loaders) == 0 {
		return nil
	}
	for _, hook := range c.onConfigChangeHooks {
		if err := hook(c.Services); err != nil {
			return err
		}
	}
	return nil
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
func LoadConfig(_ context.Context, key, file string) (*Config, error) {
	config := &Config{}

	// Create default loader if none provided
	loader, err := NewEnvironmentLoader(key, file)
	if err != nil {
		return nil, err
	}

	// Load initial configuration
	config.AddLoader(loader)
	if err := loader.Load(config); err != nil {
		return nil, err
	}

	return config, nil
}
