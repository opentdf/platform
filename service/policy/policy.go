package policy

import (
	"embed"

	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/opentdf/platform/service/policy/attributes"
	"github.com/opentdf/platform/service/policy/db/migrations"
	"github.com/opentdf/platform/service/policy/db/migrations_sqlite"
	"github.com/opentdf/platform/service/policy/kasregistry"
	"github.com/opentdf/platform/service/policy/keymanagement"
	"github.com/opentdf/platform/service/policy/namespaces"
	"github.com/opentdf/platform/service/policy/obligations"
	"github.com/opentdf/platform/service/policy/registeredresources"
	"github.com/opentdf/platform/service/policy/resourcemapping"
	"github.com/opentdf/platform/service/policy/subjectmapping"
	"github.com/opentdf/platform/service/policy/unsafe"
)

// Migrations is the default PostgreSQL migrations filesystem.
// Deprecated: Use MigrationsForDriver instead.
var Migrations *embed.FS

// MigrationsPostgres is the PostgreSQL migrations filesystem.
var MigrationsPostgres *embed.FS

// MigrationsSQLite is the SQLite migrations filesystem.
var MigrationsSQLite *embed.FS

func init() {
	Migrations = &migrations.FS
	MigrationsPostgres = &migrations.FS
	MigrationsSQLite = &migrations_sqlite.FS
}

// MigrationsForDriver returns the appropriate migrations filesystem for the given driver type.
func MigrationsForDriver(driver db.DriverType) *embed.FS {
	switch driver {
	case db.DriverSQLite:
		return MigrationsSQLite
	default:
		return MigrationsPostgres
	}
}

func NewRegistrations() []serviceregistry.IService {
	registrations := []serviceregistry.IService{}
	namespace := "policy"
	dbRegister := serviceregistry.DBRegister{
		Required:            true,
		Migrations:          Migrations,
		MigrationsForDriver: MigrationsForDriver,
	}

	registrations = append(registrations, []serviceregistry.IService{
		attributes.NewRegistration(namespace, dbRegister),
		namespaces.NewRegistration(namespace, dbRegister),
		resourcemapping.NewRegistration(namespace, dbRegister),
		subjectmapping.NewRegistration(namespace, dbRegister),
		kasregistry.NewRegistration(namespace, dbRegister),
		unsafe.NewRegistration(namespace, dbRegister),
		actions.NewRegistration(namespace, dbRegister),
		registeredresources.NewRegistration(namespace, dbRegister),
		keymanagement.NewRegistration(namespace, dbRegister),
		obligations.NewRegistration(namespace, dbRegister),
	}...)
	return registrations
}
