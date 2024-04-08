package integration

import "github.com/opentdf/platform/service/internal/config"

const (
	nonExistentAttributeValueUUID = "78909865-8888-9999-9999-000000000000"
)

var Config *config.Config

func init() {
	Config = &config.Config{}

	Config.DB.User = "postgres"
	Config.DB.Password = "postgres"
	Config.DB.Host = "localhost"
	Config.DB.Port = 5432
	Config.DB.Database = "opentdf-test"
}
