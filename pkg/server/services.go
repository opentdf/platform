package server

import (
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/services/kasregistry"
	"github.com/opentdf/platform/services/policy/attributes"
	"github.com/opentdf/platform/services/policy/namespaces"
	"github.com/opentdf/platform/services/policy/resourcemapping"
	"github.com/opentdf/platform/services/policy/subjectmapping"
)

func registerServices() {
	// Register the services
	serviceregistry.RegisterService(namespaces.NewRegistration())
	serviceregistry.RegisterService(resourcemapping.NewRegistration())
	serviceregistry.RegisterService(subjectmapping.NewRegistration())
	serviceregistry.RegisterService(attributes.NewRegistration())
	serviceregistry.RegisterService(kasregistry.NewRegistration())
}
