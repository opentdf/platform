package entityresolution

import (
	"github.com/mitchellh/mapstructure"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	claims "github.com/opentdf/platform/service/entityresolution/claims"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type ERSConfig struct {
	Mode string `mapstructure:"mode" json:"mode"`
}

const (
	KeycloakMode = "keycloak"
	ClaimsMode   = "claims"
)

type EntityResolution struct {
	entityresolution.EntityResolutionServiceServer
}

func NewRegistration() *serviceregistry.Service[EntityResolution] {
	return &serviceregistry.Service[EntityResolution]{
		ServiceOptions: serviceregistry.ServiceOptions[EntityResolution]{
			Namespace:   "entityresolution",
			ServiceDesc: &entityresolution.EntityResolutionService_ServiceDesc,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (*EntityResolution, serviceregistry.HandlerServer) {
				var inputConfig ERSConfig

				if err := mapstructure.Decode(srp.Config, &inputConfig); err != nil {
					panic(err)
				}
				if inputConfig.Mode == ClaimsMode {
					claimsSVC, claimsHandler := claims.RegisterClaimsERS(srp.Config, srp.Logger)
					return &EntityResolution{EntityResolutionServiceServer: claimsSVC}, claimsHandler
				}

				// Default to keyclaok ERS
				kcSVC, kcHandler := keycloak.RegisterKeycloakERS(srp.Config, srp.Logger)
				return &EntityResolution{EntityResolutionServiceServer: kcSVC}, kcHandler
			},
		},
	}
}
