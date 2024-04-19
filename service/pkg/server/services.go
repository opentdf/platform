package server

import (
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/services/authorization"
	"github.com/opentdf/platform/services/health"
	"github.com/opentdf/platform/services/kas"
	"github.com/opentdf/platform/services/policy"
	wellknown "github.com/opentdf/platform/services/wellknownconfiguration"
)

func registerServices() error {
	services := []serviceregistry.Registration{
		health.NewRegistration(),
		authorization.NewRegistration(),
		kas.NewRegistration(),
		wellknown.NewRegistration(),
	}
	services = append(services, policy.NewRegistrations()...)

	// Register the services
	for _, s := range services {
		if err := serviceregistry.RegisterService(s); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}
