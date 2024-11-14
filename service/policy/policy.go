package policy

import (
	"embed"

	configv1 "github.com/opentdf/platform/protocol/go/config/v1"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy/attributes"
	"github.com/opentdf/platform/service/policy/db/migrations"
	"github.com/opentdf/platform/service/policy/kasregistry"
	"github.com/opentdf/platform/service/policy/namespaces"
	"github.com/opentdf/platform/service/policy/resourcemapping"
	"github.com/opentdf/platform/service/policy/subjectmapping"
	"github.com/opentdf/platform/service/policy/unsafe"
)

var Migrations *embed.FS

func init() {
	Migrations = &migrations.FS
}

func NewRegistrations() []serviceregistry.Registration {
	registrations := []serviceregistry.Registration{}
	namespace := "policy"
	dbRegister := serviceregistry.DBRegister{
		Required:   true,
		Migrations: Migrations,
	}
	svcConfigRegister := serviceregistry.ServiceConfigRegister{
		Proto: &configv1.PolicyConfig{},
	}

	for _, r := range []serviceregistry.Registration{
		attributes.NewRegistration(),
		namespaces.NewRegistration(),
		resourcemapping.NewRegistration(),
		subjectmapping.NewRegistration(),
		kasregistry.NewRegistration(),
		unsafe.NewRegistration(),
	} {
		r.Namespace = namespace
		r.DB = dbRegister
		r.ServiceConfig = svcConfigRegister
		registrations = append(registrations, r)
	}
	return registrations
}
