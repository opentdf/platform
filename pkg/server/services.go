package server

import (
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/services/health"
	"github.com/opentdf/platform/services/kasregistry"
	"github.com/opentdf/platform/services/policy/attributes"
	"github.com/opentdf/platform/services/policy/namespaces"
	"github.com/opentdf/platform/services/policy/resourcemapping"
	"github.com/opentdf/platform/services/policy/subjectmapping"
)

func registerServices() error {
	// Register the services
	if err := serviceregistry.RegisterService(namespaces.NewRegistration()); err != nil {
		return err
	}

	if err := serviceregistry.RegisterService(resourcemapping.NewRegistration()); err != nil {
		return err
	}

	if err := serviceregistry.RegisterService(subjectmapping.NewRegistration()); err != nil {
		return err
	}

	if err := serviceregistry.RegisterService(attributes.NewRegistration()); err != nil {
		return err
	}

	if err := serviceregistry.RegisterService(kasregistry.NewRegistration()); err != nil {
		return err
	}

	if err := serviceregistry.RegisterService(health.NewRegistration()); err != nil {
		return err
	}
	return nil
}
