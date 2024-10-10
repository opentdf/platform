package entityresolution

import (
	"github.com/mitchellh/mapstructure"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	dummy "github.com/opentdf/platform/service/entityresolution/dummy"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

// type EntityResolutionService struct { //nolint:revive // allow for simple naming
// 	entityresolution.UnimplementedEntityResolutionServiceServer
// 	idpConfig map[string]any //keycloak.KeycloakConfig
// 	logger    *logger.Logger
// }

type ERSConfig struct {
	Mode string `mapstructure:"mode" json:"mode"`
}

const KeycloakMode = "keycloak"
const DummyMode = "dummy"

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "entityresolution",
		ServiceDesc: &entityresolution.EntityResolutionService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			var inputConfig ERSConfig

			if err := mapstructure.Decode(srp.Config, &inputConfig); err != nil {
				panic(err)
			}
			if inputConfig.Mode == DummyMode {
				return dummy.RegisterDummyERS(srp.Config, srp.Logger)
			}

			return keycloak.RegisterKeycloakERS(srp.Config, srp.Logger)
		},
	}
}
