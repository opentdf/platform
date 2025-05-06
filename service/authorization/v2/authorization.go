package v2

import (
	"context"

	"connectrpc.com/connect"
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type AuthorizationService struct {
	// TODO: add rest of struct dependencies from V1 AuthorizationService
	logger *logger.Logger
}

func OnConfigUpdate(as *AuthorizationService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		// TODO: implement logic from V1 AuthorizationService

		as.logger.Info("AuthorizationService V2 config updated")

		return nil
	}
}

func NewRegistration() *serviceregistry.Service[authorizationv2connect.AuthorizationServiceHandler] {
	as := new(AuthorizationService)
	onUpdateConfig := OnConfigUpdate(as)

	return &serviceregistry.Service[authorizationv2connect.AuthorizationServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[authorizationv2connect.AuthorizationServiceHandler]{
			Namespace:      "authorization",
			ServiceDesc:    &authorizationv2.AuthorizationService_ServiceDesc,
			ConnectRPCFunc: authorizationv2connect.NewAuthorizationServiceHandler,
			OnConfigUpdate: onUpdateConfig,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (authorizationv2connect.AuthorizationServiceHandler, serviceregistry.HandlerServer) {
				// TODO: add registration logic from V1 AuthorizationService
				return as, nil
			},
		},
	}
}

// TODO: implement RPC methods

func (a *AuthorizationService) GetDecision(context.Context, *connect.Request[authorizationv2.GetDecisionRequest]) (*connect.Response[authorizationv2.GetDecisionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (a *AuthorizationService) GetDecisionBulk(context.Context, *connect.Request[authorizationv2.GetDecisionBulkRequest]) (*connect.Response[authorizationv2.GetDecisionBulkResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (a *AuthorizationService) GetDecisionBulkByToken(context.Context, *connect.Request[authorizationv2.GetDecisionBulkByTokenRequest]) (*connect.Response[authorizationv2.GetDecisionBulkByTokenResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (a *AuthorizationService) GetDecisionByToken(context.Context, *connect.Request[authorizationv2.GetDecisionByTokenRequest]) (*connect.Response[authorizationv2.GetDecisionByTokenResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (a *AuthorizationService) GetEntitlements(context.Context, *connect.Request[authorizationv2.GetEntitlementsRequest]) (*connect.Response[authorizationv2.GetEntitlementsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
