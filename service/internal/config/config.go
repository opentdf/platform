package config

import (
	"errors"
	"fmt"
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
	ErrLoadingConfig Error = "error loading config"
)

// Load config with viper.
func LoadConfig(key string, file string) (*Config, error) {
	config := &Config{}
	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}
	viper.AddConfigPath(fmt.Sprintf("%s/."+key, homedir))
	viper.AddConfigPath("." + key)
	viper.AddConfigPath(".")
	viper.SetConfigName(key)
	viper.SetConfigType("yaml")

	// Default config values (non-zero)
	viper.SetDefault("server.auth.cache_refresh_interval", "15m")

	viper.SetEnvPrefix(key)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Allow for a custom config file to be passed in
	// This takes precedence over the AddConfigPath/SetConfigName
	if file != "" {
		viper.SetConfigFile(file)
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

	if err := defaults.Set(config); err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

	err = viper.Unmarshal(config)
	if err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

	return config, nil
}
