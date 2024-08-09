package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/creasty/defaults"
	"github.com/go-playground/validator/v10"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/pkg/util"
	"github.com/spf13/viper"
)

// Config represents the configuration settings for the service.
type Config struct {
	// DevMode specifies whether the service is running in development mode.
	DevMode bool `mapstructure:"dev_mode"`

	// DB represents the configuration settings for the database.
	DB db.Config `mapstructure:"db"`

	// Server represents the configuration settings for the server.
	Server server.Config `mapstructure:"server"`

	// Logger represents the configuration settings for the logger.
	Logger logger.Config `mapstructure:"logger"`

	// Mode specifies which services to run.
	// By default, it runs all services.
	Mode []string `mapstructure:"mode" default:"[\"all\"]"`

	// SDKConfig represents the configuration settings for the SDK.
	SDKConfig SDKConfig `mapstructure:"sdk_config"`

	// Services represents the configuration settings for the services.
	Services map[string]serviceregistry.ServiceConfig `mapstructure:"services"`
}

// SDKConfig represents the configuration for the SDK.
type SDKConfig struct {
	// Endpoint is the URL of the Core Platform endpoint.
	Endpoint string `mapstructure:"endpoint"`

	// Plaintext specifies whether the SDK should use plaintext communication.
	Plaintext bool `mapstructure:"plaintext" default:"false" validate:"boolean"`

	// ClientID is the client ID used for client credentials grant.
	// It is required together with ClientSecret.
	ClientID string `mapstructure:"client_id" validate:"required_with=ClientSecret"`

	// ClientSecret is the client secret used for client credentials grant.
	// It is required together with ClientID.
	ClientSecret string `mapstructure:"client_secret" validate:"required_with=ClientID"`
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
func LoadConfig(key, file string) (*Config, error) {
	config := &Config{}

	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Join(err, ErrLoadingConfig)
	}

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

	// Validate Config
	validate := validator.New()

	if err := validate.Struct(config); err != nil {
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
