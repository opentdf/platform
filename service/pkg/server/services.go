package server

import (
	"github.com/arkavo-org/opentdf-platform/service/authorization"
	"github.com/arkavo-org/opentdf-platform/service/health"
	"github.com/arkavo-org/opentdf-platform/service/kas"
	"github.com/arkavo-org/opentdf-platform/service/kasregistry"
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	"github.com/arkavo-org/opentdf-platform/service/policy/attributes"
	"github.com/arkavo-org/opentdf-platform/service/policy/namespaces"
	"github.com/arkavo-org/opentdf-platform/service/policy/resourcemapping"
	"github.com/arkavo-org/opentdf-platform/service/policy/subjectmapping"
	wellknown "github.com/arkavo-org/opentdf-platform/service/wellknownconfiguration"
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
		authorization.NewRegistration(),
		kas.NewRegistration(),
		wellknown.NewRegistration(),
	} {
		if err := serviceregistry.RegisterService(s); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}
