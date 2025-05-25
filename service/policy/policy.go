package policy

import (
	"embed"

	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/opentdf/platform/service/policy/attributes"
	"github.com/opentdf/platform/service/policy/db/migrations"
	"github.com/opentdf/platform/service/policy/kasregistry"
	"github.com/opentdf/platform/service/policy/keymanagement"
	"github.com/opentdf/platform/service/policy/namespaces"
	"github.com/opentdf/platform/service/policy/registeredresources"
	"github.com/opentdf/platform/service/policy/resourcemapping"
	"github.com/opentdf/platform/service/policy/subjectmapping"
	"github.com/opentdf/platform/service/policy/unsafe"
)

var Migrations *embed.FS

func init() {
	Migrations = &migrations.FS
}

func NewRegistrations() []serviceregistry.IService {
	registrations := []serviceregistry.IService{}
	namespace := "policy"
	dbRegister := serviceregistry.DBRegister{
		Required:   true,
		Migrations: Migrations,
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
	}...)
	return registrations
}
