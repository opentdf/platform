package entityresolution

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/mitchellh/mapstructure"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type EntityResolutionService struct { //nolint:revive // allow for simple naming
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig keycloak.KeycloakConfig
	logger    *logger.Logger
}

func NewRegistration() *serviceregistry.Service[entityresolutionconnect.EntityResolutionServiceHandler] {
	return &serviceregistry.Service[entityresolutionconnect.EntityResolutionServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[entityresolutionconnect.EntityResolutionServiceHandler]{
			Namespace:   "entityresolution",
			ServiceDesc: &entityresolution.EntityResolutionService_ServiceDesc,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (entityresolutionconnect.EntityResolutionServiceHandler, serviceregistry.HandlerServer) {
				var inputIdpConfig keycloak.KeycloakConfig

				if err := mapstructure.Decode(srp.Config, &inputIdpConfig); err != nil {
					panic(err)
				}

				srp.Logger.Debug("entity_resolution configuration", "config", inputIdpConfig)
				es := &EntityResolutionService{idpConfig: inputIdpConfig, logger: srp.Logger}
				return es, func(_ context.Context, _ *http.ServeMux, _ any) {}
			},
			ConnectRPCFunc: entityresolutionconnect.NewEntityResolutionServiceHandler,
		},
	}
}

func (s EntityResolutionService) ResolveEntities(ctx context.Context, req *connect.Request[entityresolution.ResolveEntitiesRequest]) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
	resp, err := keycloak.EntityResolution(ctx, req.Msg, s.idpConfig, s.logger)
	return &connect.Response[entityresolution.ResolveEntitiesResponse]{Msg: &resp}, err
}

func (s EntityResolutionService) CreateEntityChainFromJwt(ctx context.Context, req *connect.Request[entityresolution.CreateEntityChainFromJwtRequest]) (*connect.Response[entityresolution.CreateEntityChainFromJwtResponse], error) {
	resp, err := keycloak.CreateEntityChainFromJwt(ctx, req.Msg, s.idpConfig, s.logger)
	return &connect.Response[entityresolution.CreateEntityChainFromJwtResponse]{Msg: &resp}, err
}
