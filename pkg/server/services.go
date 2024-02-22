package server

import (
	"github.com/opentdf/opentdf-v2-poc/pkg/serviceregistry"
	"github.com/opentdf/opentdf-v2-poc/services/attributes"
	"github.com/opentdf/opentdf-v2-poc/services/kasregistry"
	"github.com/opentdf/opentdf-v2-poc/services/namespaces"
	"github.com/opentdf/opentdf-v2-poc/services/resourcemapping"
	"github.com/opentdf/opentdf-v2-poc/services/subjectmapping"
)

func registerServices() {
	// Register the services
	serviceregistry.RegisterService(namespaces.NewRegistration())
	serviceregistry.RegisterService(resourcemapping.NewRegistration())
	serviceregistry.RegisterService(subjectmapping.NewRegistration())
	serviceregistry.RegisterService(attributes.NewRegistration())
	serviceregistry.RegisterService(kasregistry.NewRegistration())
}
