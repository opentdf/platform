package integration

import "github.com/opentdf/platform/internal/config"

var Config *config.Config

func init() {
	Config = &config.Config{}

	Config.DB.User = "postgres"
	Config.DB.Password = "postgres"
	Config.DB.Host = "localhost"
	Config.DB.Port = 5432
	Config.DB.Database = "opentdf-test"
}
