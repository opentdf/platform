package entityresolution

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type EntityResolutionService struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig keycloak.KeycloakConfig
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "entityresolution",
		ServiceDesc: &entityresolution.EntityResolutionService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			var inputIdpConfig keycloak.KeycloakConfig
			confJSON, err := json.Marshal(srp.Config.ExtraProps)
			if err != nil {
				panic(err)
			}
			err = json.Unmarshal(confJSON, &inputIdpConfig)
			if err != nil {
				panic(err)
			}
			return &EntityResolutionService{idpConfig: inputIdpConfig}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				return entityresolution.RegisterEntityResolutionServiceHandlerServer(ctx, mux, server.(entityresolution.EntityResolutionServiceServer))
			}
		},
	}
}

func (s EntityResolutionService) ResolveEntities(ctx context.Context, req *entityresolution.EntityResolutionRequest) (*entityresolution.EntityResolutionResponse, error) {
	slog.Info("request", "", req)
	resp, err := keycloak.EntityResolution(ctx, req, s.idpConfig)
	return &resp, err
}
