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

const LoaderNameFile = "config-file"

// FileLoader implements Loader using Viper
type FileLoader struct {
	viper *viper.Viper
}

// NewConfigFileLoader creates a new Viper-based configuration loader
// to load from a default or specified file.
func NewConfigFileLoader(key, file string) (*FileLoader, error) {
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

	return &FileLoader{viper: v}, nil
}

// Get fetches a particular config value by dot-delimited key from the source
func (l *FileLoader) Get(key string) (any, error) {
	return l.viper.Get(key), nil
}

// GetConfigKeys returns all the configuration keys found in the config file.
func (l *FileLoader) GetConfigKeys() ([]string, error) {
	return l.viper.AllKeys(), nil
}

// Load loads the configuration into the provided struct
func (l *FileLoader) Load(_ Config) error {
	// Read the config file
	if err := l.viper.ReadInConfig(); err != nil {
		return errors.Join(err, ErrLoadingConfig)
	}
	return nil
}

// Watch starts watching the config file for configuration changes
func (l *FileLoader) Watch(ctx context.Context, _ *Config, onChange func(context.Context) error) error {
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

func (l *FileLoader) Name() string {
	return LoaderNameFile
}

func (l *FileLoader) Close() error {
	return nil
}
