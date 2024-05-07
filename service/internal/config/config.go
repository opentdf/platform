package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/spf13/viper"
)

type Config struct {
	DB       db.Config                                `yaml:"db"`
	OPA      opa.Config                               `yaml:"opa"`
	Server   server.Config                            `yaml:"server"`
	Logger   logger.Config                            `yaml:"logger"`
	Services map[string]serviceregistry.ServiceConfig `yaml:"services" default:"{\"policy\": {\"enabled\": true}, \"health\": {\"enabled\": true}, \"authorization\": {\"enabled\": true}, \"wellknown\": {\"enabled\": true}}"`
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
