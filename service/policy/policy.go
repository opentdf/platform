package policy

import (
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/services/policy/attributes"
	"github.com/opentdf/platform/services/policy/db/migrations"
	"github.com/opentdf/platform/services/policy/kasregistry"
	"github.com/opentdf/platform/services/policy/namespaces"
	"github.com/opentdf/platform/services/policy/resourcemapping"
	"github.com/opentdf/platform/services/policy/subjectmapping"
)

func NewRegistrations() []serviceregistry.Registration {
	registrations := []serviceregistry.Registration{}
	namespace := "policy"
	dbRegister := serviceregistry.DBRegister{
		MigrationsFS: &migrations.FS,
	}

	for _, r := range []serviceregistry.Registration{
		attributes.NewRegistration(),
		namespaces.NewRegistration(),
		resourcemapping.NewRegistration(),
		subjectmapping.NewRegistration(),
		attributes.NewRegistration(),
		kasregistry.NewRegistration(),
	} {
		r.Namespace = namespace
		r.DBRegister = dbRegister
		registrations = append(registrations, r)
	}

	return registrations
}
