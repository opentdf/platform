package entityresolution

import (
	"github.com/mitchellh/mapstructure"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"
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
	entityresolutionconnect.EntityResolutionServiceHandler
}

func NewRegistration() *serviceregistry.Service[entityresolutionconnect.EntityResolutionServiceHandler] {
	return &serviceregistry.Service[entityresolutionconnect.EntityResolutionServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[entityresolutionconnect.EntityResolutionServiceHandler]{
			Namespace:      "entityresolution",
			ServiceDesc:    &entityresolution.EntityResolutionService_ServiceDesc,
			ConnectRPCFunc: entityresolutionconnect.NewEntityResolutionServiceHandler,
			GRPCGateayFunc: entityresolution.RegisterEntityResolutionServiceHandlerFromEndpoint,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (entityresolutionconnect.EntityResolutionServiceHandler, serviceregistry.HandlerServer) {
				var inputConfig ERSConfig

				if err := mapstructure.Decode(srp.Config, &inputConfig); err != nil {
					panic(err)
				}
				if inputConfig.Mode == ClaimsMode {
					claimsSVC, claimsHandler := claims.RegisterClaimsERS(srp.Config, srp.Logger)
					return EntityResolution{EntityResolutionServiceHandler: claimsSVC}, claimsHandler
				}

				// Default to keycloak ERS
				kcSVC, kcHandler := keycloak.RegisterKeycloakERS(srp.Config, srp.Logger)
				return EntityResolution{EntityResolutionServiceHandler: kcSVC}, kcHandler
			},
		},
	}
}
