package config

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/viper"
)

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
func (l *EnvironmentValueLoader) Watch(ctx context.Context, _ *Config, onChange func(context.Context) error) error {
	// Environment variables can't be watched directly, so we poll them.
	interval := defaultWatchViaPollInterval
	slog.DebugContext(ctx, "starting environment configuration polling", slog.Duration("interval", interval))

	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				slog.DebugContext(ctx, "polling environment variables for changes")
				// Create a temporary viper instance to read the current state of environment variables.
				currentEnvViper := viper.New()
				currentEnvViper.SetEnvPrefix(l.viper.GetEnvPrefix())
				currentEnvViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
				currentEnvViper.AutomaticEnv()

				changed := false
				if l.allowListMap != nil {
					// If there's an allow list, only check those keys for changes.
					for key := range l.allowListMap {
						oldValue := l.viper.Get(key)
						newValue := currentEnvViper.Get(key)
						if !reflect.DeepEqual(oldValue, newValue) {
							slog.DebugContext(ctx, "environment config change detected",
								slog.String("key", key),
								slog.Any("old_value", oldValue),
								slog.Any("new_value", newValue))
							changed = true
							break
						}
					}
				} else if !reflect.DeepEqual(l.viper.AllSettings(), currentEnvViper.AllSettings()) {
					slog.DebugContext(ctx, "environment config change detected: settings map differs")
					changed = true
				}

				if changed {
					// The state has changed. Update our loader's viper instance to reflect the new state for the next check.
					l.viper = currentEnvViper
					// Trigger the main config reload function.
					if err := onChange(ctx); err != nil {
						slog.ErrorContext(ctx, "error processing environment config change", slog.Any("error", err))
					}
				}
			case <-ctx.Done():
				slog.DebugContext(ctx, "stopping environment configuration polling")
				return
			}
		}
	}()

	return nil
}

// Name returns the name of the environment configuration loader
func (l *EnvironmentValueLoader) Name() string {
	return "environment-value"
}

// Close closes the environment configuration loader
func (l *EnvironmentValueLoader) Close() error {
	// No-op on a viper-based loader, which does not provide a close method
	return nil
}
