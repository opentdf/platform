package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	authzV2Connect "github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	otdf "github.com/opentdf/platform/sdk"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
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

func NewRegistration() *serviceregistry.Service[authzV2Connect.AuthorizationServiceHandler] {
	as := new(AuthorizationService)

	return &serviceregistry.Service[authzV2Connect.AuthorizationServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[authzV2Connect.AuthorizationServiceHandler]{
			Namespace:      "authorization",
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

// GetEntitlements for an entity chain
func (as *AuthorizationService) GetEntitlements(ctx context.Context, req *connect.Request[authzV2.GetEntitlementsRequest]) (*connect.Response[authzV2.GetEntitlementsResponse], error) {
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
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	entitlements, err := pdp.GetEntitlements(ctx, entityIdentifier, withComprehensiveHierarchy)
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

// GetDecision for an entity chain and an action on a single resource
func (as *AuthorizationService) GetDecision(ctx context.Context, req *connect.Request[authzV2.GetDecisionRequest]) (*connect.Response[authzV2.GetDecisionResponse], error) {
	as.logger.DebugContext(ctx, "getting decision")

	ctx, span := as.Tracer.Start(ctx, "GetDecision")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	request := req.Msg
	entityIdentifier := request.GetEntityIdentifier()
	action := request.GetAction()
	resource := request.GetResource()

	decisions, permitted, err := pdp.GetDecision(ctx, entityIdentifier, action, []*authzV2.Resource{resource})
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp, err := rollupSingleResourceDecision(permitted, decisions)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to rollup single resource decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resp), nil
}

// GetDecisionMultiResource for an entity chain and action on multiple resources
func (as *AuthorizationService) GetDecisionMultiResource(ctx context.Context, req *connect.Request[authzV2.GetDecisionMultiResourceRequest]) (*connect.Response[authzV2.GetDecisionMultiResourceResponse], error) {
	as.logger.DebugContext(ctx, "getting decision multi resource")

	ctx, span := as.Tracer.Start(ctx, "GetDecisionMultiResource")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	request := req.Msg
	entityIdentifier := request.GetEntityIdentifier()
	action := request.GetAction()
	resources := request.GetResources()

	decisions, allPermitted, err := pdp.GetDecision(ctx, entityIdentifier, action, resources)
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resourceDecisions, err := rollupMultiResourceDecision(decisions)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to rollup multi resource decision", slog.String("error", err.Error()))
		return nil, err
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
func (as *AuthorizationService) GetDecisionBulk(_ context.Context, req *connect.Request[authzV2.GetDecisionBulkRequest]) (*connect.Response[authzV2.GetDecisionBulkResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecisionBulk not implemented"))
}

// rollupMultiResourceDecision creates a standardized response for multi-resource decisions
// by processing the decisions returned from the PDP.
func rollupMultiResourceDecision(
	decisions []*access.Decision,
) ([]*authzV2.ResourceDecision, error) {
	if len(decisions) == 0 {
		return nil, errors.New("no decisions returned")
	}

	resourceDecisions := make([]*authzV2.ResourceDecision, 0, len(decisions))

	for idx, decision := range decisions {
		if decision == nil {
			return nil, fmt.Errorf("nil decision at index %d", idx)
		}
		if len(decision.Results) == 0 {
			return nil, errors.New("no decision results returned")
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

	return resourceDecisions, nil
}

// rollupSingleResourceDecision creates a standardized response for a single resource decision
// by processing the decision returned from the PDP.
func rollupSingleResourceDecision(
	permitted bool,
	decisions []*access.Decision,
) (*authzV2.GetDecisionResponse, error) {
	if len(decisions) == 0 {
		return nil, errors.New("no decisions returned")
	}

	decision := decisions[0]
	if decision == nil {
		return nil, errors.New("nil decision at index 0")
	}

	if len(decision.Results) == 0 {
		return nil, errors.New("no decision results returned")
	}

	result := decision.Results[0]
	access := authzV2.Decision_DECISION_DENY
	if permitted {
		access = authzV2.Decision_DECISION_PERMIT
	}
	resourceDecision := &authzV2.ResourceDecision{
		Decision:            access,
		EphemeralResourceId: result.ResourceID,
	}
	return &authzV2.GetDecisionResponse{
		Decision: resourceDecision,
	}, nil
}
