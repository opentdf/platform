package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/logger"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	"github.com/spf13/viper"
)

type Config struct {
	DB      db.Config     `yaml:"db"`
	OPA     opa.Config    `yaml:"opa"`
	Server  server.Config `yaml:"server"`
	OpenTDF OpenTDFConfig `yaml:"services" mapstructure:"services"`
	Logger  logger.Config `yaml:"logger"`
}

type OpenTDFConfig struct {
}

type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	ErrLoadingConfig Error = "error loading config"
)

// Load config with viper.
func LoadConfig() (*Config, error) {
	config := &Config{}
	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}
	viper.AddConfigPath(fmt.Sprintf("%s/.opentdf", homedir))
	viper.AddConfigPath(".opentdf")
	viper.AddConfigPath(".")
	viper.SetConfigName("opentdf")
	viper.SetConfigType("yaml")

	viper.SetEnvPrefix("opentdf")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

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
