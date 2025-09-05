package config

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/creasty/defaults"
	"github.com/spf13/viper"
)

const LoaderNameDefaultSettings = "default-settings"

// DefaultSettingsLoader implements Loader using Viper
type DefaultSettingsLoader struct {
	KVMap map[string]any
	viper *viper.Viper
}

func getDefaultKVsInternal(data map[string]any, prefix string, defaultKVs *map[string]any) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		if nestedMap, ok := value.(map[string]any); ok {
			// Only add nested keys.
			getDefaultKVsInternal(nestedMap, fullKey, defaultKVs)
		} else {
			(*defaultKVs)[fullKey] = value
		}
	}
}

// getDefaultKVs flattens config to a map of dotted key paths pointing to default config values.
func getDefaultKVs() (map[string]any, error) {
	// Create default config
	config := &Config{}
	if err := defaults.Set(config); err != nil {
		return nil, errors.Join(err, ErrSettingConfig)
	}
	defaultConfigKVMapBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var defaultConfigMap map[string]interface{}
	err = json.Unmarshal(defaultConfigKVMapBytes, &defaultConfigMap)
	if err != nil {
		return nil, err
	}
	defaultKVs := map[string]any{}
	getDefaultKVsInternal(defaultConfigMap, "", &defaultKVs)
	return defaultKVs, nil
}

// NewDefaultSettingsLoader creates a new Viper-based configuration loader
// to hold default config.
func NewDefaultSettingsLoader() (*DefaultSettingsLoader, error) {
	defaultConfigKVMap, err := getDefaultKVs()
	if err != nil {
		return nil, err
	}

	defaultViper := viper.NewWithOptions(viper.WithLogger(slog.Default()))
	for defaultConfigKey, defaultConfigValue := range defaultConfigKVMap {
		defaultViper.SetDefault(defaultConfigKey, defaultConfigValue)
	}

	result := &DefaultSettingsLoader{
		KVMap: defaultConfigKVMap,
		viper: defaultViper,
	}
	return result, nil
}

// Get fetches a particular config value by dot-delimited key from the source
func (l *DefaultSettingsLoader) Get(key string) (any, error) {
	return l.viper.Get(key), nil
}

// GetConfigKeys returns all the default configuration keys pulled from the Config struct.
func (l *DefaultSettingsLoader) GetConfigKeys() ([]string, error) {
	return l.viper.AllKeys(), nil
}

// Load loads the configuration into the provided struct
func (l *DefaultSettingsLoader) Load(_ Config) error {
	return nil
}

func (l *DefaultSettingsLoader) Watch(_ context.Context, _ *Config, _ func(context.Context) error) error {
	return nil
}

func (l *DefaultSettingsLoader) Name() string {
	return LoaderNameDefaultSettings
}

func (l *DefaultSettingsLoader) Close() error {
	return nil
}
