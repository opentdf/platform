package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/go-playground/validator/v10"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/tracing"
	"github.com/spf13/viper"
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
	Services ServicesMap `mapstructure:"services" json:"services"`

	// Trace is for configuring open telemetry based tracing.
	Trace tracing.Config `mapstructure:"trace" json:"trace"`

	// onConfigChangeHooks is a list of functions to call when the configuration changes.
	onConfigChangeHooks []ChangeHook
	// loaders is a list of configuration loaders.
	loaders []Loader
	// reloadMux ensures that the Reload function is thread-safe.
	reloadMux *sync.Mutex
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
		// onChangeCallback is the function that will be called by loaders when a change is detected.
		// It orchestrates the reloading of the entire configuration and then triggers the registered hooks.
		loaderName := loader.Name()
		onChangeCallback := func(ctx context.Context) error {
			slog.InfoContext(ctx, "configuration change detected, reloading...", slog.String("loader", loaderName))
			if err := c.Reload(ctx); err != nil {
				slog.ErrorContext(ctx, "failed to reload configuration", slog.Any("error", err))
				return err
			}
			slog.InfoContext(ctx, "configuration reloaded successfully")

			// Now call the user-provided hooks with the new configuration.
			return c.OnChange(ctx)
		}
		if err := loader.Watch(ctx, c, onChangeCallback); err != nil {
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
func (c *Config) OnChange(ctx context.Context) error {
	if len(c.onConfigChangeHooks) == 0 {
		return nil
	}
	slog.DebugContext(ctx, "executing configuration change hooks")
	for _, hook := range c.onConfigChangeHooks {
		if err := hook(c.Services); err != nil {
			return err
		}
	}
	return nil
}

// Reload re-reads and merges configuration from all registered loaders.
// It is thread-safe and handles dependencies between loaders by iterating
// until the configuration stabilizes.
func (c *Config) Reload(ctx context.Context) error {
	// Lock to ensure only one reload operation happens at a time.
	c.reloadMux.Lock()
	defer c.reloadMux.Unlock()

	// This loop handles dependencies between loaders. It continues to iterate
	// until a full pass over all loaders adds no new configuration values.
	// This ensures that a loader can use configuration provided by another
	// loader that appears later in the priority list.
	var assigned map[string]struct{}
	for {
		lastAssignedCount := len(assigned)
		assigned = make(map[string]struct{})
		orderedViper := viper.NewWithOptions(viper.WithLogger(slog.Default()))

		// Loop through loaders in their order of priority.
		for _, loader := range c.loaders {
			// The Load call allows the loader to refresh its internal state (e.g., re-read file, re-query DB).
			// It uses the config `c` from the *previous* iteration to configure itself if needed.
			if err := loader.Load(*c); err != nil {
				return fmt.Errorf("loader %s failed to load: %w", loader.Name(), err)
			}

			// Get all keys this loader knows about.
			keys, err := loader.GetConfigKeys()
			if err != nil {
				slog.WarnContext(
					ctx,
					"loader failed to get config keys",
					slog.String("loader", loader.Name()),
					slog.Any("error", err),
				)
				continue
			}

			// Merge values from the current loader into Viper.
			for _, key := range keys {
				// If a higher-priority loader already set this key, skip.
				if _, assignedAlready := assigned[key]; assignedAlready {
					continue
				}
				loaderValue, err := loader.Get(key)
				if err != nil {
					slog.WarnContext(
						ctx,
						"loader.Get failed for a reported key",
						slog.String("loader", loader.Name()),
						slog.String("key", key),
						slog.Any("error", err),
					)
					continue
				}
				if loaderValue != nil {
					orderedViper.Set(key, loaderValue)
					assigned[key] = struct{}{}
				}
			}
		}

		// Unmarshal the merged configuration into the main config struct `c`
		// so it's available for the next iteration of the dependency loop.
		if err := orderedViper.Unmarshal(c); err != nil {
			return errors.Join(err, ErrUnmarshallingConfig)
		}

		// If no new keys were assigned in this pass, the configuration has stabilized.
		if len(assigned) == lastAssignedCount {
			break
		}
	}

	// Final validation after the configuration has converged.
	if err := validator.New().Struct(c); err != nil {
		return errors.Join(err, ErrUnmarshallingConfig)
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

// Deprecated: Use the `Load` method with your preferred loaders
func LoadConfig(ctx context.Context, key, file string) (*Config, error) {
	envLoader, err := NewEnvironmentValueLoader(key, nil)
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}
	configFileLoader, err := NewConfigFileLoader(key, file)
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}
	defaultSettingsLoader, err := NewDefaultSettingsLoader()
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}
	return Load(
		ctx,
		envLoader,
		configFileLoader,
		defaultSettingsLoader,
	)
}

// Load loads configuration using the provided loaders
func Load(ctx context.Context, loaders ...Loader) (*Config, error) {
	config := &Config{
		loaders:   loaders,
		reloadMux: &sync.Mutex{},
	}

	if err := config.Reload(ctx); err != nil {
		return nil, err
	}

	return config, nil
}
