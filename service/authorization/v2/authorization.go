package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	authzConnect "github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	otdf "github.com/opentdf/platform/sdk"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const EntityIDPrefix string = "entity_idx_"

var ErrEmptyStringAttribute = errors.New("resource attributes must have at least one attribute value fqn")

type AuthorizationService struct { //nolint:revive // AuthorizationService is a valid name for this struct
	sdk    *otdf.SDK
	config *Config
	logger *logger.Logger
	trace.Tracer
}

type Config struct{}

func OnConfigUpdate(as *AuthorizationService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		err := mapstructure.Decode(cfg, as.config)
		if err != nil {
			return fmt.Errorf("invalid auth svc cfg [%v] %w", cfg, err)
		}

		as.logger.Info("authorization service config reloaded")

		return nil
	}
}

func NewRegistration() *serviceregistry.Service[authzConnect.AuthorizationServiceHandler] {
	as := new(AuthorizationService)
	onUpdateConfig := OnConfigUpdate(as)

	return &serviceregistry.Service[authzConnect.AuthorizationServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[authzConnect.AuthorizationServiceHandler]{
			Namespace:      "authorization",
			ServiceDesc:    &authzV2.AuthorizationService_ServiceDesc,
			ConnectRPCFunc: authzConnect.NewAuthorizationServiceHandler,
			OnConfigUpdate: onUpdateConfig,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (authzConnect.AuthorizationServiceHandler, serviceregistry.HandlerServer) {
				authZCfg := new(Config)

				logger := srp.Logger

				// default ERS endpoint
				as.sdk = srp.SDK
				as.logger = logger
				if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
					logger.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
				}

				// Read in config defaults only on first register
				// if err := defaults.Set(authZCfg); err != nil {
				// 	panic(fmt.Errorf("failed to set defaults for authorization service config: %w", err))
				// }

				// Only decode config if it exists
				// if srp.Config != nil {
				// 	if err := mapstructure.Decode(srp.Config, &authZCfg); err != nil {
				// 		panic(fmt.Errorf("invalid auth svc cfg [%v] %w", srp.Config, err))
				// 	}
				// }

				as.config = authZCfg
				as.Tracer = srp.Tracer
				logger.Debug("authorization service config")

				return as, nil
			},
		},
	}
}

// TODO: Not sure what we want to check here?
func (as AuthorizationService) IsReady(ctx context.Context) error {
	as.logger.TraceContext(ctx, "checking readiness of authorization service")
	return nil
}

func (as *AuthorizationService) GetEntitlements(ctx context.Context, req *connect.Request[authzV2.GetEntitlementsRequest]) (*connect.Response[authzV2.GetEntitlementsResponse], error) {
	as.logger.DebugContext(ctx, "getting entitlements")

	ctx, span := as.Tracer.Start(ctx, "GetEntitlements")
	defer span.End()

	entities := req.Msg.GetEntities()
	withComprehensiveHierarchy := req.Msg.GetWithComprehensiveHierarchy()

	// TODO: this should be moved to proto validation https://github.com/opentdf/platform/issues/1057
	if entities == nil {
		as.logger.ErrorContext(ctx, "requires entities")
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("requires entities"))
	}

	// When authorization service can consume cached policy, switch to the other PDP (process based on policy passed in)
	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	entitlements, err := pdp.GetEntitlements(ctx, entities, withComprehensiveHierarchy)
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get entitlements", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	rsp := &authzV2.GetEntitlementsResponse{
		Entitlements: entitlements,
	}

	return connect.NewResponse(rsp), nil
}

// GetDecision for an entity chain and action on a single resource
func (as *AuthorizationService) GetDecision(ctx context.Context, req *connect.Request[authzV2.GetDecisionRequest]) (*connect.Response[authzV2.GetDecisionResponse], error) {
	as.logger.DebugContext(ctx, "getting decision")

	ctx, span := as.Tracer.Start(ctx, "GetDecision")
	defer span.End()

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	request := req.Msg
	ec := request.GetEntity()
	action := request.GetAction()
	resource := request.GetResource()

	decisions, permitted, err := pdp.GetDecision(ctx, ec, action, []*authzV2.Resource{resource})
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(decisions) == 0 {
		as.logger.ErrorContext(ctx, "no decisions returned")
		return nil, connect.NewError(connect.CodeInternal, errors.New("no decisions returned"))
	}
	decision := decisions[0]
	if len(decision.Results) == 0 {
		as.logger.ErrorContext(ctx, "no decision results returned")
		return nil, connect.NewError(connect.CodeInternal, errors.New("no decision results returned"))
	}
	result := decision.Results[0]
	access := authzV2.Decision_DECISION_DENY
	if permitted {
		access = authzV2.Decision_DECISION_PERMIT
	}

	resp := &authzV2.GetDecisionResponse{
		EphemeralEntityChainId: ec.GetEphemeralId(),
		Action:                 action,
		Decision: &authzV2.ResourceDecision{
			Decision:            access,
			EphemeralResourceId: result.ResourceID,
		},
	}

	return connect.NewResponse(resp), nil
}

func (as *AuthorizationService) GetDecisionMultiResource(ctx context.Context, req *connect.Request[authzV2.GetDecisionMultiResourceRequest]) (*connect.Response[authzV2.GetDecisionMultiResourceResponse], error) {
	as.logger.DebugContext(ctx, "getting decision multi resource")

	ctx, span := as.Tracer.Start(ctx, "GetDecisionMultiResource")
	defer span.End()

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	request := req.Msg
	ec := request.GetEntity()
	action := request.GetAction()
	resources := request.GetResources()

	decisions, allPermitted, err := pdp.GetDecision(ctx, ec, action, resources)
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resourceDecisions := make([]*authzV2.ResourceDecision, 0, len(decisions))
	for idx, decision := range decisions {
		if len(decision.Results) == 0 {
			as.logger.ErrorContext(ctx, "no decision results returned")
			return nil, connect.NewError(connect.CodeInternal, errors.New("no decision results returned"))
		}
		result := decision.Results[0]
		access := authzV2.Decision_DECISION_DENY
		if decision.Access {
			access = authzV2.Decision_DECISION_PERMIT
		}
		resourceDecision := &authzV2.ResourceDecision{
			Decision:            access,
			EphemeralResourceId: result.ResourceID,
		}
		resourceDecisions[idx] = resourceDecision
	}

	resp := &authzV2.GetDecisionMultiResourceResponse{
		EphemeralEntityChainId: ec.GetEphemeralId(),
		Action:                 action,
		AllPermitted: &wrapperspb.BoolValue{
			Value: allPermitted,
		},
		ResourceDecisions: resourceDecisions,
	}

	return connect.NewResponse(resp), nil
}

func (as *AuthorizationService) GetDecisionBulk(ctx context.Context, req *connect.Request[authzV2.GetDecisionBulkRequest]) (*connect.Response[authzV2.GetDecisionBulkResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecisionBulk not implemented"))
}
func (as *AuthorizationService) GetDecisionByToken(ctx context.Context, req *connect.Request[authzV2.GetDecisionByTokenRequest]) (*connect.Response[authzV2.GetDecisionByTokenResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecisionByToken not implemented"))
}

