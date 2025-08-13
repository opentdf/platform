package config

import (
	"context"
	"log/slog"

	"github.com/spf13/viper"
)

// DefaultSettingsLoader implements Loader using Viper
type DefaultSettingsLoader struct {
	KVMap map[string]any
	viper *viper.Viper
	name  string
}

// NewDefaultSettingsLoader creates a new Viper-based configuration loader
// to hold default config.
func NewDefaultSettingsLoader() (*DefaultSettingsLoader, error) {
	defaultConfigKVMap, err := GetDefaultKVs()
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

// Load loads the configuration into the provided struct
func (l *DefaultSettingsLoader) Load() error {
	// Unmarshal config
	//if err := l.viper.Unmarshal(cfg); err != nil {
	//	return errors.Join(err, ErrUnmarshallingConfig)
	//}

	// Validate config
	//validate := validator.New()
	//if err := validate.Struct(cfg); err != nil {
	//	return errors.Join(err, ErrUnmarshallingConfig)
	//}

	return nil
}

func (l *DefaultSettingsLoader) Watch(ctx context.Context, cfg *Config, onChange func(context.Context) error) error {
	return nil
}

func (l *DefaultSettingsLoader) Name() string {
	return "default-settings"
}

func (l *DefaultSettingsLoader) Close() error {
	return nil
}
