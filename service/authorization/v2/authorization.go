package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/protocol/go/authorization"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	authzConnect "github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	ers "github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
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

// GetEntitlements for an entity chain
func (as *AuthorizationService) GetEntitlements(ctx context.Context, req *connect.Request[authzV2.GetEntitlementsRequest]) (*connect.Response[authzV2.GetEntitlementsResponse], error) {
	as.logger.DebugContext(ctx, "getting entitlements")

	ctx, span := as.Tracer.Start(ctx, "GetEntitlements")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	entityChain := req.Msg.GetEntityChain()
	withComprehensiveHierarchy := req.Msg.GetWithComprehensiveHierarchy()

	// TODO: this should be moved to proto validation https://github.com/opentdf/platform/issues/1057
	if entityChain == nil {
		as.logger.ErrorContext(ctx, "requires an entity chain but was nil")
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("requires an entity chain"))
	}

	// When authorization service can consume cached policy, switch to the other PDP (process based on policy passed in)
	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	entitlements, err := pdp.GetEntitlements(ctx, entityChain, withComprehensiveHierarchy)
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

// GetEntitlementsByToken for an entity represented by an access token
func (as *AuthorizationService) GetEntitlementsByToken(ctx context.Context, req *connect.Request[authzV2.GetEntitlementsByTokenRequest]) (*connect.Response[authzV2.GetEntitlementsByTokenResponse], error) {
	as.logger.DebugContext(ctx, "getting entitlements by token")

	ctx, span := as.Tracer.Start(ctx, "GetEntitlementsByToken")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	token := req.Msg.GetToken()
	entityChain, err := as.getOneEntityChainFromToken(ctx, token)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get an entity chain from JWT", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	withComprehensiveHierarchy := req.Msg.GetWithComprehensiveHierarchy()

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	entitlements, err := pdp.GetEntitlements(ctx, entityChain, withComprehensiveHierarchy)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get entitlements", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	rsp := &authzV2.GetEntitlementsByTokenResponse{
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
	entityChain := request.GetEntity()
	action := request.GetAction()
	resource := request.GetResource()

	decisions, permitted, err := pdp.GetDecision(ctx, entityChain, action, []*authzV2.Resource{resource})
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
		Decision: &authzV2.ResourceDecision{
			Decision:            access,
			EphemeralResourceId: result.ResourceID,
		},
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
	ec := request.GetEntity()
	action := request.GetAction()
	resources := request.GetResources()

	decisions, allPermitted, err := pdp.GetDecision(ctx, ec, action, resources)
	if err != nil {
		// TODO: any bad request errors that aren't 500s?
		as.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resourceDecisions, err := rollupMultiResourceDecision(ctx, decisions)
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

// GetDecisionBulk for an entity represented by an access token and an action on a single resource
func (as *AuthorizationService) GetDecisionByToken(ctx context.Context, req *connect.Request[authzV2.GetDecisionByTokenRequest]) (*connect.Response[authzV2.GetDecisionByTokenResponse], error) {
	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	ctx, span := as.Tracer.Start(ctx, "GetDecisionByToken")
	defer span.End()

	tok := req.Msg.GetToken()
	entityChain, err := as.getOneEntityChainFromToken(ctx, tok)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get an entity chain from JWT", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	action := req.Msg.GetAction()
	resource := req.Msg.GetResource()
	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	decisions, permitted, err := pdp.GetDecision(ctx, entityChain, action, []*authzV2.Resource{resource})
	if err != nil {
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
	resp := &authzV2.GetDecisionByTokenResponse{
		DecisionResponse: &authzV2.GetDecisionResponse{
			Decision: &authzV2.ResourceDecision{
				Decision:            access,
				EphemeralResourceId: result.ResourceID,
			},
		},
	}
	return connect.NewResponse(resp), nil
}

// GetDecisionByTokenMultiResource for an entity represented by an access token and an action on multiple resources
func (as *AuthorizationService) GetDecisionByTokenMultiResource(ctx context.Context, req *connect.Request[authzV2.GetDecisionByTokenMultiResourceRequest]) (*connect.Response[authzV2.GetDecisionByTokenMultiResourceResponse], error) {
	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	ctx, span := as.Tracer.Start(ctx, "GetDecisionByTokenMultiResource")
	defer span.End()

	as.logger.DebugContext(ctx, "getting decision by token for multiple resources")

	token := req.Msg.GetToken()
	entityChain, err := as.getOneEntityChainFromToken(ctx, token)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get an entity chain from JWT", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	action := req.Msg.GetAction()
	resources := req.Msg.GetResources()

	// Create policy decision point and get decisions
	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to create JIT PDP", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	decisions, allPermitted, err := pdp.GetDecision(ctx, entityChain, action, resources)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get decision", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Build resource decisions
	resourceDecisions, err := rollupMultiResourceDecision(ctx, decisions)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to rollup multi resource decision", slog.String("error", err.Error()))
		return nil, err
	}

	// Construct and return response
	resp := &authzV2.GetDecisionByTokenMultiResourceResponse{
		AllPermitted: &wrapperspb.BoolValue{
			Value: allPermitted,
		},
		ResourceDecisions: resourceDecisions,
	}

	return connect.NewResponse(resp), nil
}

// GetDecisionBulk for multiple requests, each comprising a combination of entity chain, action, and one or more resources
func (as *AuthorizationService) GetDecisionBulk(ctx context.Context, req *connect.Request[authzV2.GetDecisionBulkRequest]) (*connect.Response[authzV2.GetDecisionBulkResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetDecisionBulk not implemented"))
}

// getOneEntityChainFromToken extracts the entity chain from the token
func (as *AuthorizationService) getOneEntityChainFromToken(ctx context.Context, token *authorization.Token) (*authzV2.EntityChain, error) {
	convertTokenRequest := &ers.CreateEntityChainFromJwtRequest{Tokens: []*authorization.Token{
		token,
	}}
	entityChainFromJWT, err := as.sdk.EntityResoution.CreateEntityChainFromJwt(ctx, convertTokenRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create entity chain from JWT: %w", err)
	}
	if entityChainFromJWT == nil {
		return nil, errors.New("failed to create entity chain from JWT, nil response")
	}

	if len(entityChainFromJWT.GetEntityChains()) == 0 {
		return nil, errors.New("failed to create entity chain from JWT, empty entity chain")
	}

	chain := entityChainFromJWT.GetEntityChains()[0]
	if chain == nil {
		return nil, errors.New("failed to create entity chain from JWT, nil entity chain")
	}
	
	chainV2 := &authzV2.EntityChain{
		EphemeralChainId: chain.GetId(),
		Entities:         make([]*authzV2.Entity, 0, len(chain.GetEntities())),
	}
	for idx, entity := range chain.GetEntities() {
		entityV2 := &authzV2.Entity{
			EphemeralId: entity.GetId(),
			EntityType:  entity.GetEntityType(),
			Category:    entity.GetCategory(),
		}
		chainV2.Entities[idx] = entityV2
	}

	return chainV2, nil
}

// rollupMultiResourceDecision creates a standardized response for multi-resource decisions
// by processing the decisions returned from the PDP.
func rollupMultiResourceDecision(
	ctx context.Context,
	decisions []*access.Decision,
) ([]*authzV2.ResourceDecision, error) {
	resourceDecisions := make([]*authzV2.ResourceDecision, 0, len(decisions))

	for idx, decision := range decisions {
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
	ctx context.Context,
	entityID string,
	action *policy.Action,
	permitted bool,
	decisions []*access.Decision,
) (*authzV2.GetDecisionResponse, error) {
	if len(decisions) == 0 {
		return nil, connect.NewError(connect.CodeInternal, errors.New("no decisions returned"))
	}
	decision := decisions[0]
	if len(decision.Results) == 0 {
		return nil, connect.NewError(connect.CodeInternal, errors.New("no decision results returned"))
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
