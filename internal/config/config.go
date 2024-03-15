package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/logger"
	"github.com/opentdf/platform/internal/opa"
	"github.com/opentdf/platform/internal/server"
	"github.com/opentdf/platform/pkg/serviceregistry"
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
func LoadConfig(key string) (*Config, error) {
	if key == "" {
		key = "opentdf"
		slog.Info("LoadConfig: key not provided, using default", "config", key)
	} else {
		slog.Info("LoadConfig", "config", key)
	}

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

	viper.SetEnvPrefix(key)
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

	// Manually handle unmarshaling of ExtraProps for each service
	for serviceKey, service := range config.Services {
		var extraProps map[string]interface{}
		if err := viper.UnmarshalKey("services."+serviceKey, &extraProps); err != nil {
			return nil, errors.Join(err, ErrLoadingConfig)
		}
		service.ExtraProps = extraProps

		// Remove "enabled" from ExtraProps
		delete(extraProps, "enabled")

		config.Services[serviceKey] = service // Update the service in the map
	}

	return config, nil
}
