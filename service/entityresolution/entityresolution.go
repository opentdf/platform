package entityresolution

import (
	"context"
	"encoding/json"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type EntityResolutionService struct { //nolint:revive // allow for simple naming
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig keycloak.KeycloakConfig
	logger    *logger.Logger
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
			return &EntityResolutionService{idpConfig: inputIdpConfig, logger: srp.Logger}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				return entityresolution.RegisterEntityResolutionServiceHandlerServer(ctx, mux, server.(entityresolution.EntityResolutionServiceServer)) //nolint:forcetypeassert // allow type assert, following other services
			}
		},
	}
}

func (s EntityResolutionService) ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest) (*entityresolution.ResolveEntitiesResponse, error) {
	s.logger.Debug("request", "", req)
	resp, err := keycloak.EntityResolution(ctx, req, s.idpConfig, s.logger)
	return &resp, err
}

func (s EntityResolutionService) CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	s.logger.Debug("request", "", req)
	resp, err := keycloak.CreateEntityChainFromJwt(ctx, req, s.idpConfig, s.logger)
	return &resp, err
}
