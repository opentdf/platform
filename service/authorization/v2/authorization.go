package authorization

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	authzV2Connect "github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

				as.sdk = srp.SDK
				as.logger = logger

				// if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
				// 	logger.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
				// }

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
func (as *Service) GetEntitlements(ctx context.Context, req *connect.Request[authzV2.GetEntitlementsRequest]) (*connect.Response[authzV2.GetEntitlementsResponse], error) {
	as.logger.DebugContext(ctx, "getting entitlements")

	ctx, span := as.Tracer.Start(ctx, "GetEntitlements")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	entityIdentifier := req.Msg.GetEntityIdentifier()
	withComprehensiveHierarchy := req.Msg.GetWithComprehensiveHierarchy()

	// When authorization service can consume cached policy, switch to the other PDP (process based on policy passed in)
	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.Any("error", err))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	entitlements, err := pdp.GetEntitlements(ctx, entityIdentifier, withComprehensiveHierarchy)
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get entitlements", slog.Any("error", err))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	rsp := &authzV2.GetEntitlementsResponse{
		Entitlements: entitlements,
	}

	return connect.NewResponse(rsp), nil
}

// GetDecision for an entity chain and an action on a single resource
func (as *Service) GetDecision(ctx context.Context, req *connect.Request[authzV2.GetDecisionRequest]) (*connect.Response[authzV2.GetDecisionResponse], error) {
	as.logger.DebugContext(ctx, "getting decision")

	ctx, span := as.Tracer.Start(ctx, "GetDecision")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.Any("error", err))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	request := req.Msg
	entityIdentifier := request.GetEntityIdentifier()
	action := request.GetAction()
	resource := request.GetResource()

	decisions, permitted, err := pdp.GetDecision(ctx, entityIdentifier, action, []*authzV2.Resource{resource})
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get decision", slog.Any("error", err), slog.Any("request", request))
		if errors.Is(err, access.ErrFQNNotFound) || errors.Is(err, access.ErrDefinitionNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp, err := rollupSingleResourceDecision(permitted, decisions)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to rollup single-resource decision", slog.Any("error", err), slog.Any("request", request))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resp), nil
}

// GetDecisionMultiResource for an entity chain and action on multiple resources
func (as *Service) GetDecisionMultiResource(ctx context.Context, req *connect.Request[authzV2.GetDecisionMultiResourceRequest]) (*connect.Response[authzV2.GetDecisionMultiResourceResponse], error) {
	as.logger.DebugContext(ctx, "getting decision multi resource")

	ctx, span := as.Tracer.Start(ctx, "GetDecisionMultiResource")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(errors.New("failed to create JIT PDP"), err))
	}
	request := req.Msg
	entityIdentifier := request.GetEntityIdentifier()
	action := request.GetAction()
	resources := request.GetResources()

	decisions, allPermitted, err := pdp.GetDecision(ctx, entityIdentifier, action, resources)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(errors.New("failed to get decision"), err), slog.Any("request", request))
	}

	resourceDecisions, err := rollupMultiResourceDecisions(decisions)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(errors.New("failed to rollup multi-resource decision"), err), slog.Any("request", request))
	}

	resp := &authzV2.GetDecisionMultiResourceResponse{
		AllPermitted: &wrapperspb.BoolValue{
			Value: allPermitted,
		},
		ResourceDecisions: resourceDecisions,
	}

	return connect.NewResponse(resp), nil
}

// GetDecisionBulk for multiple requests, each comprising a combination of entity chain, action, and one or more resources
func (as *Service) GetDecisionBulk(ctx context.Context, req *connect.Request[authzV2.GetDecisionBulkRequest]) (*connect.Response[authzV2.GetDecisionBulkResponse], error) {
	as.logger.DebugContext(ctx, "getting decision bulk")

	ctx, span := as.Tracer.Start(ctx, "GetDecisionBulk")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(errors.New("failed to create JIT PDP"), err))
	}

	multiRequests := req.Msg.GetDecisionRequests()
	decisionResponses := make([]*authzV2.GetDecisionMultiResourceResponse, len(multiRequests))

	// TODO: revisit performance of this loop after introduction of caching and registered resource values within decisioning,
	// as the same entity in multiple requests should only be resolved JIT once, not once per request if the same in each.
	for idx, request := range multiRequests {
		entityIdentifier := request.GetEntityIdentifier()
		action := request.GetAction()
		resources := request.GetResources()

		decisions, allPermitted, err := pdp.GetDecision(ctx, entityIdentifier, action, resources)
		if err != nil {
			return nil, statusifyError(ctx, as.logger, errors.Join(errors.New("failed to get bulk decision"), err), slog.Any("request", request))
		}

		resourceDecisions, err := rollupMultiResourceDecisions(decisions)
		if err != nil {
			return nil, statusifyError(ctx, as.logger, errors.Join(errors.New("failed to rollup bulk multi-resource decision"), err), slog.Any("request", request), slog.Int("index", idx))
		}

		decisionResponse := &authzV2.GetDecisionMultiResourceResponse{
			AllPermitted: &wrapperspb.BoolValue{
				Value: allPermitted,
			},
			ResourceDecisions: resourceDecisions,
		}
		decisionResponses[idx] = decisionResponse
	}

	rsp := &authzV2.GetDecisionBulkResponse{
		DecisionResponses: decisionResponses,
	}
	return connect.NewResponse(rsp), nil
}
