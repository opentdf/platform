package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/fsnotify/fsnotify"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// ConfigLoader defines the interface for loading and managing configuration
type ConfigLoader interface {
	// Load loads the configuration into the provided struct
	Load(cfg *Config) error

	// Watch starts watching for configuration changes, returning a watcher function
	Watch(ctx context.Context, cfg *Config) (ConfigWatcher, error)

	// Close closes the configuration loader
	Close() error

	// GetName returns the name of the configuration loader
	GetName() string
}

// EnvironmentLoader implements ConfigLoader using Viper
type EnvironmentLoader struct {
	viper *viper.Viper
}

// NewEnvironmentLoader creates a new Viper-based configuration loader
// to load from environment variables, from a default or specified file
// (or k8s config map), or some combination
func NewEnvironmentLoader(key, file string) (*EnvironmentLoader, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

	// Set paths and config file info
	v := viper.NewWithOptions(viper.WithLogger(slog.Default()))
	v.AddConfigPath(fmt.Sprintf("%s/."+key, homedir))
	v.AddConfigPath("." + key)
	v.AddConfigPath(".")
	v.SetConfigName(key)
	v.SetConfigType("yaml")

	// Default config values (non-zero)
	v.SetDefault("server.auth.cache_refresh_interval", "15m")

	// Environment variable settings
	v.SetEnvPrefix(key)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Allow for a custom config file to be passed in
	// This takes precedence over the AddConfigPath/SetConfigName
	if file != "" {
		v.SetConfigFile(file)
	}

	// Read the config file
	if err := v.ReadInConfig(); err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

	return &EnvironmentLoader{viper: v}, nil
}

// Load loads the configuration into the provided struct
func (l *EnvironmentLoader) Load(cfg *Config) error {
	// Set defaults
	if err := defaults.Set(cfg); err != nil {
		return errors.Join(err, ErrSettingConfig)
	}

	// Unmarshal config
	if err := l.viper.Unmarshal(cfg); err != nil {
		return errors.Join(err, ErrUnmarshallingConfig)
	}

	// Validate config
	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		return errors.Join(err, ErrUnmarshallingConfig)
	}

	return nil
}

// Watch starts watching the config file for configuration changes
func (l *EnvironmentLoader) Watch(_ context.Context, cfg *Config) (ConfigWatcher, error) {
	l.viper.WatchConfig()

	// Create a slice to store all the hook functions
	var configChangeHooks []ConfigChangeHook

	// Return a function that allows registering hooks
	onConfigChange := func(hook ConfigChangeHook) {
		configChangeHooks = append(configChangeHooks, hook)
	}

	// Register only one viper config change handler
	l.viper.OnConfigChange(func(e fsnotify.Event) {
		slog.Info("Config file changed", "file", e.Name)

		// First reload and validate the config
		if err := l.Load(cfg); err != nil {
			slog.Error("Error reloading config", "error", err)
			return
		}

		slog.Info("Config successfully reloaded", "config", cfg.LogValue())

		// Then execute all registered hooks with the event
		for _, hook := range configChangeHooks {
			hook(cfg.Services)
		}
	})

	return onConfigChange, nil
}

// GetName returns the name of the environment configuration loader
func (l *EnvironmentLoader) GetName() string {
	return "environment"
}

// Close closes the environment configuration loader
func (l *EnvironmentLoader) Close() error {
	// No-op on a viper-based loader, which does not provide a close method
	return nil
}
