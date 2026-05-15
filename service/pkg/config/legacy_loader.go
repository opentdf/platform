package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

const LoaderNameLegacy = "legacy"

// LegacyLoader enables loading values from a YAML file and the environment together
type LegacyLoader struct {
	viper *viper.Viper
}

// NewLegacyLoader creates a new Viper-based configuration loader
// to load from a default or specified file.
func NewLegacyLoader(key, file string) (*LegacyLoader, error) {
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

	return &LegacyLoader{viper: v}, nil
}

// Get fetches a particular config value by dot-delimited key from the source
func (l *LegacyLoader) Get(key string) (any, error) {
	return l.viper.Get(key), nil
}

// GetConfigKeys returns all the configuration keys found in the config file.
func (l *LegacyLoader) GetConfigKeys() ([]string, error) {
	return l.viper.AllKeys(), nil
}

// Load is called to load/refresh the configuration from its source
func (l *LegacyLoader) Load(cfg Config) error {
	// Read the config file
	if err := l.viper.ReadInConfig(); err != nil {
		return errors.Join(err, ErrLoadingConfig)
	}

	err := l.viper.Unmarshal(&cfg)

	return err
}

// Watch starts watching the config file for configuration changes
func (l *LegacyLoader) Watch(ctx context.Context, _ *Config, onChange func(context.Context) error) error {
	l.viper.WatchConfig()

	// If config changes, trigger the main config reload function
	l.viper.OnConfigChange(func(e fsnotify.Event) {
		slog.DebugContext(ctx, "config file changed, triggering reload", slog.String("file", e.Name))

		if err := onChange(ctx); err != nil {
			slog.ErrorContext(ctx, "error processing config file change", slog.Any("error", err))
		}
	})

	return nil
}

func (l *LegacyLoader) Name() string {
	return LoaderNameLegacy
}

func (l *LegacyLoader) Close() error {
	return nil
}
