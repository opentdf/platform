package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/creasty/defaults"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/pkg/util"
	"github.com/spf13/viper"
)

type Config struct {
	DevMode bool          `mapstructure:"dev_mode"`
	DB      db.Config     `mapstructure:"db"`
	Server  server.Config `mapstructure:"server"`
	Logger  logger.Config `mapstructure:"logger"`
	// Defines which services to run
	Mode      []string                                 `mapsctructure:"mode"`
	SDKConfig SDKConfig                                `mapstructure:"sdk_config"`
	Services  map[string]serviceregistry.ServiceConfig `mapstructure:"services"`
}

type SDKConfig struct {
	Endpoint     string `mapstructure:"endpoint"`
	Plaintext    bool   `mapstructure:"plaintext" default:"false"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	ErrLoadingConfig       Error = "error loading config"
	ErrUnmarshallingConfig Error = "error unmarshalling config"
	ErrSettingConfig       Error = "error setting config"
)

// LoadConfig Load config with viper.
func LoadConfig(key string, file string) (*Config, error) {
	config := &Config{}
	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}
	// uncommment to debug config loading,
	// issue is the loglevel directive is in the config yaml
	// t := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	// 	Level: slog.LevelDebug,
	// })
	// v := viper.NewWithOptions(viper.WithLogger(slog.New(t)))
	v := viper.NewWithOptions(viper.WithLogger(slog.Default()))
	v.AddConfigPath(fmt.Sprintf("%s/."+key, homedir))
	v.AddConfigPath("." + key)
	v.AddConfigPath(".")
	v.SetConfigName(key)
	v.SetConfigType("yaml")

	// Default config values (non-zero)
	v.SetDefault("server.auth.cache_refresh_interval", "15m")

	v.SetEnvPrefix(key)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Allow for a custom config file to be passed in
	// This takes precedence over the AddConfigPath/SetConfigName
	if file != "" {
		v.SetConfigFile(file)
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

	if err := defaults.Set(config); err != nil {
		return nil, errors.Join(err, ErrSettingConfig)
	}

	err = v.Unmarshal(config)
	if err != nil {
		return nil, errors.Join(err, ErrUnmarshallingConfig)
	}

	return config, nil
}

func (c *Config) LogValue() slog.Value {
	redactedConfig := util.RedactSensitiveData(c)
	var values []slog.Attr
	v := reflect.ValueOf(redactedConfig).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		key := fieldType.Tag.Get("yaml")
		if key == "" {
			key = fieldType.Name
		}
		values = append(values, slog.String(key, util.StructToString(field)))
	}
	return slog.GroupValue(values...)
}
