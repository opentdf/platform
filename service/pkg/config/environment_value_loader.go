package config

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

const LoaderNameEnvironmentValue = "environment-value"

// EnvironmentValueLoader implements Loader using Viper
type EnvironmentValueLoader struct {
	allowListMap map[string]struct{}
	viper        *viper.Viper
}

// NewEnvironmentValueLoader creates a new Viper-based configuration loader
// to load from environment variables, from a default or specified file
// (or k8s config map), or some combination
func NewEnvironmentValueLoader(key string, allowList []string) (*EnvironmentValueLoader, error) {
	// Set paths and config file info
	v := viper.NewWithOptions(viper.WithLogger(slog.Default()))

	// Environment variable settings
	v.SetEnvPrefix(key)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var allowListMap map[string]struct{}
	if allowList != nil || len(allowList) > 0 {
		allowListMap = make(map[string]struct{})
		for _, allow := range allowList {
			allowListMap[allow] = struct{}{}
		}
	}

	result := &EnvironmentValueLoader{
		allowListMap: allowListMap,
		viper:        v,
	}
	return result, nil
}

// Get fetches a particular config value by dot-delimited key from the source
func (l *EnvironmentValueLoader) Get(key string) (any, error) {
	if l.allowListMap != nil {
		if _, keyInAllowList := l.allowListMap[key]; !keyInAllowList {
			return nil, fmt.Errorf("environment value %s is not allowed", key)
		}
	}
	return l.viper.Get(key), nil
}

// GetConfigKeys returns all the configuration keys found in the environment variables.
func (l *EnvironmentValueLoader) GetConfigKeys() ([]string, error) {
	return l.viper.AllKeys(), nil
}

// Load loads the configuration into the provided struct
func (l *EnvironmentValueLoader) Load(_ Config) error {
	// For environment variables, Viper's `AutomaticEnv` handles this, so no explicit load is needed here.
	return nil
}

// Watch starts watching the config file for configuration changes
func (l *EnvironmentValueLoader) Watch(_ context.Context, _ *Config, _ func(context.Context) error) error {
	// Environment variables can't be watched.
	return nil
}

// Name returns the name of the environment configuration loader
func (l *EnvironmentValueLoader) Name() string {
	return LoaderNameEnvironmentValue
}

// Close closes the environment configuration loader
func (l *EnvironmentValueLoader) Close() error {
	// No-op on a viper-based loader, which does not provide a close method
	return nil
}
