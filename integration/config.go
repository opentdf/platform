package integration

import "github.com/opentdf/opentdf-v2-poc/internal/config"

var Config *config.Config

func init() {
	Config = &config.Config{}

	Config.DB.User = "postgres"
	Config.DB.Password = "postgres"
	Config.DB.Host = "localhost"
	Config.DB.Port = 5432
	Config.DB.Database = "opentdf-test"
}
