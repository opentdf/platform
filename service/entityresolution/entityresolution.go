package entityresolution

import (
	"context"
	"encoding/json"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type EntityResolutionService struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig *keycloak.KeycloakConfig
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "entityresolution",
		ServiceDesc: &entityresolution.EntityResolutionService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			var idpConfig keycloak.KeycloakConfig
			confJSON, err := json.Marshal(srp.Config.ExtraProps)
			if err != nil {
				panic(err)
			}
			err = json.Unmarshal(confJSON, &idpConfig)
			if err != nil {
				panic(err)
			}
			return &EntityResolutionService{idpConfig: &idpConfig}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				return entityresolution.RegisterEntityResolutionServiceHandlerServer(ctx, mux, server.(entityresolution.EntityResolutionServiceServer))
			}
		},
	}
}

func (s EntityResolutionService) ResolveEntities(req *entityresolution.EntityResolutionRequest) (*entityresolution.EntityResolutionResponse, error) {
	resp, err := keycloak.EntityResolution(context.Background(), req, *s.idpConfig)
	return &resp, err
}
