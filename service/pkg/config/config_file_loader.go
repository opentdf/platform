package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// ConfigFileLoader implements Loader using Viper
type ConfigFileLoader struct {
	viper *viper.Viper
	name  string
}

// NewConfigFileLoader creates a new Viper-based configuration loader
// to load from a default or specified file.
func NewConfigFileLoader(key, file string) (*ConfigFileLoader, error) {
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

	// Allow for a custom config file to be passed in
	// This takes precedence over the AddConfigPath/SetConfigName
	if file != "" {
		v.SetConfigFile(file)
	}

	return &ConfigFileLoader{viper: v}, nil
}

// Get fetches a particular config value by dot-delimited key from the source
func (l *ConfigFileLoader) Get(key string) (any, error) {
	return l.viper.Get(key), nil
}

// Load loads the configuration into the provided struct
func (l *ConfigFileLoader) Load() error {
	// Read the config file
	if err := l.viper.ReadInConfig(); err != nil {
		return errors.Join(err, ErrLoadingConfig)
	}

	// Validate config
	//validate := validator.New()
	//if err := validate.Struct(cfg); err != nil {
	//	return errors.Join(err, ErrUnmarshallingConfig)
	//}

	return nil
}

// Watch starts watching the config file for configuration changes
func (l *ConfigFileLoader) Watch(ctx context.Context, cfg *Config, onChange func(context.Context) error) error {
	if len(cfg.onConfigChangeHooks) == 0 {
		slog.DebugContext(ctx, "no config change hooks registered. Skipping environment config watch")
		return nil
	}

	l.viper.WatchConfig()

	// If config changes, reload it and invoke all hooks
	//nolint:contextcheck // false positive with external library function signature
	l.viper.OnConfigChange(func(e fsnotify.Event) {
		slog.DebugContext(ctx, "environment config file changed", slog.String("file", e.Name))

		// First reload and validate the config
		if err := l.Load(); err != nil {
			slog.ErrorContext(ctx, "error reloading environment config", slog.Any("error", err))
			return
		}

		slog.InfoContext(ctx,
			"environment config successfully reloaded",
			slog.Any("config", cfg.LogValue()),
			slog.String("config_loader_changed", l.Name()),
		)

		// Then execute all registered hooks with the event
		if err := onChange(context.Background()); err != nil {
			slog.ErrorContext(ctx,
				"error executing config change hooks",
				slog.Any("error", err),
				slog.String("config_loader_changed", l.Name()),
			)
		} else {
			slog.DebugContext(ctx,
				"config change hooks executed successfully",
				slog.String("config_loader_changed", l.Name()),
			)
		}
	})

	return nil
}

func (l *ConfigFileLoader) Name() string {
	return "config-file"
}

func (l *ConfigFileLoader) Close() error {
	return nil
}
