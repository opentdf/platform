package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/logger"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	"github.com/opentdf/opentdf-v2-poc/pkg/entitlements"
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
	Entitlements entitlements.Config `yaml:"entitlements"`
}

// Load config with viper
func LoadConfig() (*Config, error) {
	config := &Config{}
	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if err := defaults.Set(config); err != nil {
		return nil, err
	}

	err = viper.Unmarshal(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
