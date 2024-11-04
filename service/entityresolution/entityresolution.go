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

const KeycloakMode = "keycloak"
const ClaimsMode = "claims"

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "entityresolution",
		ServiceDesc: &entityresolution.EntityResolutionService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			var inputConfig ERSConfig

			if err := mapstructure.Decode(srp.Config, &inputConfig); err != nil {
				panic(err)
			}
			if inputConfig.Mode == ClaimsMode {
				return claims.RegisterClaimsERS(srp.Config, srp.Logger)
			}

			// Default to keyclaok ERS
			return keycloak.RegisterKeycloakERS(srp.Config, srp.Logger)
		},
	}
}
