package server

import (
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/services/health"
	"github.com/opentdf/platform/services/kas"
	"github.com/opentdf/platform/services/kasregistry"
	"github.com/opentdf/platform/services/policy/attributes"
	"github.com/opentdf/platform/services/policy/namespaces"
	"github.com/opentdf/platform/services/policy/resourcemapping"
	"github.com/opentdf/platform/services/policy/subjectmapping"
	wellknown "github.com/opentdf/platform/services/wellknownconfiguration"
)

func registerServices() error {
	// Register the services
	for _, s := range []serviceregistry.Registration{
		namespaces.NewRegistration(),
		resourcemapping.NewRegistration(),
		subjectmapping.NewRegistration(),
		attributes.NewRegistration(),
		kasregistry.NewRegistration(),
		health.NewRegistration(),
		kas.NewRegistration(),
		wellknown.NewRegistration(),
	} {
		if err := serviceregistry.RegisterService(s); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}
