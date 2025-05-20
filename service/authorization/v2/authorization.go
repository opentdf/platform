package authorization

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	authzV2Connect "github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

type Service struct {
	sdk    *otdf.SDK
	config *Config
	logger *logger.Logger
	trace.Tracer
}

type Config struct{}

func NewRegistration() *serviceregistry.Service[authzV2Connect.AuthorizationServiceHandler] {
	as := new(Service)

	return &serviceregistry.Service[authzV2Connect.AuthorizationServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[authzV2Connect.AuthorizationServiceHandler]{
			Namespace:      "authorization",
			Version:        "v2",
			ServiceDesc:    &authzV2.AuthorizationService_ServiceDesc,
			ConnectRPCFunc: authzV2Connect.NewAuthorizationServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (authzV2Connect.AuthorizationServiceHandler, serviceregistry.HandlerServer) {
				authZCfg := new(Config)

				logger := srp.Logger

				// default ERS endpoint
				as.sdk = srp.SDK
				as.logger = logger
				if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
					logger.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
				}

				as.config = authZCfg
				as.Tracer = srp.Tracer
				logger.Debug("authorization v2 service register func")

				return as, nil
			},
		},
	}
}

// TODO: uncomment after v1 is deprecated, as cannot have more than one readiness check under a namespace
// func (as Service) IsReady(ctx context.Context) error {
// 	as.logger.TraceContext(ctx, "checking readiness of authorization service")
// 	return nil
// }

// GetEntitlements for an entity chain
func (as *Service) GetEntitlements(_ context.Context, _ *connect.Request[authzV2.GetEntitlementsRequest]) (*connect.Response[authzV2.GetEntitlementsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetEntitlements not implemented"))
}

// GetDecision for an entity chain and an action on a single resource
func (as *Service) GetDecision(_ context.Context, _ *connect.Request[authzV2.GetDecisionRequest]) (*connect.Response[authzV2.GetDecisionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecision not implemented"))
}

// GetDecisionMultiResource for an entity chain and action on multiple resources
func (as *Service) GetDecisionMultiResource(_ context.Context, _ *connect.Request[authzV2.GetDecisionMultiResourceRequest]) (*connect.Response[authzV2.GetDecisionMultiResourceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecisionMultiResource not implemented"))
}

// GetDecisionBulk for multiple requests, each comprising a combination of entity chain, action, and one or more resources
func (as *Service) GetDecisionBulk(_ context.Context, _ *connect.Request[authzV2.GetDecisionBulkRequest]) (*connect.Response[authzV2.GetDecisionBulkResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecisionBulk not implemented"))
}
