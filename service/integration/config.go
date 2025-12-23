package integration

import (
	"os"

	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
)

var Config *config.Config

// UseSQLite returns true if tests should run against SQLite instead of PostgreSQL
func UseSQLite() bool {
	return os.Getenv("OPENTDF_TEST_DB") == "sqlite"
}

func init() {
	Config = &config.Config{}

	if UseSQLite() {
		// SQLite configuration - uses in-memory database
		Config.DB.Driver = db.DriverSQLite
		Config.DB.SQLitePath = ":memory:"
	} else {
		// PostgreSQL configuration (default)
		Config.DB.Driver = db.DriverPostgres
		Config.DB.User = "postgres"
		Config.DB.Password = "postgres"
		Config.DB.Host = "localhost"
		Config.DB.Port = 5432
		Config.DB.Database = "opentdf-test"
	}
}
