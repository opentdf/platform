package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/go-viper/mapstructure/v2"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	authzV2Connect "github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	ErrFailedToBuildRequestContext = errors.New("failed to contextualize decision request")
	ErrFailedToInitPDP             = errors.New("failed to create JIT PDP")
	ErrFailedToGetDecision         = errors.New("failed to get decision")
	ErrFailedToGetEntitlements     = errors.New("failed to get entitlements")
)

type Service struct {
	sdk    *otdf.SDK
	config *Config
	logger *logger.Logger
	trace.Tracer
	cache *EntitlementPolicyCache
}

func NewRegistration() *serviceregistry.Service[authzV2Connect.AuthorizationServiceHandler] {
	as := new(Service)

	return &serviceregistry.Service[authzV2Connect.AuthorizationServiceHandler]{
		Close: as.Close,
		ServiceOptions: serviceregistry.ServiceOptions[authzV2Connect.AuthorizationServiceHandler]{
			Namespace:      "authorization",
			Version:        "v2",
			ServiceDesc:    &authzV2.AuthorizationService_ServiceDesc,
			ConnectRPCFunc: authzV2Connect.NewAuthorizationServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (authzV2Connect.AuthorizationServiceHandler, serviceregistry.HandlerServer) {
				authZCfg := new(Config)
				l := srp.Logger

				as.sdk = srp.SDK
				as.logger = l
				as.config = authZCfg
				as.Tracer = srp.Tracer

				err := defaults.Set(authZCfg)
				if err != nil {
					l.Error("failed to set defaults for authorization service config", slog.Any("error", err))
					panic(fmt.Errorf("failed to set defaults for authorization service config: %w", err))
				}

				// Only decode config if it exists
				if srp.Config != nil {
					if err := mapstructure.Decode(srp.Config, &authZCfg); err != nil {
						l.Error("failed to decode authorization service config", slog.Any("error", err))
						panic(fmt.Errorf("invalid authorization svc config [%v] %w", srp.Config, err))
					}
				}

				if err := authZCfg.Validate(); err != nil {
					l.Error("invalid authorization service config",
						slog.Any("config", authZCfg.LogValue()),
						slog.Any("error", err),
					)
					panic(fmt.Errorf("invalid authorization svc config %w", err))
				}
				l.Debug("authorization service config", slog.Any("config", authZCfg.LogValue()))

				if !authZCfg.Cache.Enabled {
					l.Debug("entitlement policy cache is disabled")
					return as, nil
				}

				cacheClient, err := srp.NewCacheClient(cache.Options{})
				if err != nil || cacheClient == nil {
					l.Error("failed to create platform cache client", slog.Any("error", err))
					panic(fmt.Errorf("failed to create platform cache client: %w", err))
				}

				refreshInterval, err := time.ParseDuration(authZCfg.Cache.RefreshInterval)
				if err != nil {
					l.Error("failed to parse entitlement policy cache refresh interval", slog.Any("error", err))
					panic(fmt.Errorf("failed to parse entitlement policy cache refresh interval [%s]: %w", authZCfg.Cache.RefreshInterval, err))
				}

				retriever := access.NewEntitlementPolicyRetriever(as.sdk)
				as.cache, err = NewEntitlementPolicyCache(context.Background(), l, retriever, cacheClient, refreshInterval)
				if err != nil {
					l.Error("failed to create entitlement policy cache", slog.Any("error", err))
					panic(fmt.Errorf("failed to create entitlement policy cache: %w", err))
				}

				// if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
				// 	logger.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
				// }

				if authZCfg.AllowDirectEntitlements {
					l.Info("direct entitlements are enabled for authorization service")
				}

				return as, nil
			},
		},
	}
}

// Close gracefully shuts down the authorization service, closing the entitlement policy cache.
func (as *Service) Close() {
	as.logger.Info("gracefully shutting down authorization service")
	if as.cache != nil {
		as.cache.Stop()
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

	ctx, span := as.Start(ctx, "GetEntitlements")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	entityIdentifier := req.Msg.GetEntityIdentifier()
	withComprehensiveHierarchy := req.Msg.GetWithComprehensiveHierarchy()

	// When authorization service can consume cached policy, switch to the other PDP (process based on policy passed in)
	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk, as.cache, as.config.AllowDirectEntitlements)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToGetEntitlements, ErrFailedToInitPDP, err))
	}

	entitlements, err := pdp.GetEntitlements(ctx, entityIdentifier, withComprehensiveHierarchy)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToGetEntitlements, err))
	}
	rsp := &authzV2.GetEntitlementsResponse{
		Entitlements: entitlements,
	}

	return connect.NewResponse(rsp), nil
}

// GetDecision for an entity chain and an action on a single resource
func (as *Service) GetDecision(ctx context.Context, req *connect.Request[authzV2.GetDecisionRequest]) (*connect.Response[authzV2.GetDecisionResponse], error) {
	as.logger.DebugContext(ctx, "getting decision")

	ctx, span := as.Start(ctx, "GetDecision")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk, as.cache, as.config.AllowDirectEntitlements)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToInitPDP, err))
	}

	request := req.Msg
	entityIdentifier := request.GetEntityIdentifier()
	action := request.GetAction()
	resource := request.GetResource()
	fulfillableObligations := request.GetFulfillableObligationFqns()

	reqContext, err := as.getDecisionRequestContext(ctx)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, err)
	}

	decision, err := pdp.GetDecision(
		ctx,
		entityIdentifier,
		action,
		[]*authzV2.Resource{resource},
		reqContext,
		fulfillableObligations,
	)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, err)
	}

	resourceDecisions, err := rollupResourceDecisions(decision)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, err)
	}

	resp := &authzV2.GetDecisionResponse{
		Decision: resourceDecisions[0],
	}
	return connect.NewResponse(resp), nil
}

// GetDecisionMultiResource for an entity chain and action on multiple resources
func (as *Service) GetDecisionMultiResource(ctx context.Context, req *connect.Request[authzV2.GetDecisionMultiResourceRequest]) (*connect.Response[authzV2.GetDecisionMultiResourceResponse], error) {
	as.logger.DebugContext(ctx, "getting decision multi resource")

	ctx, span := as.Start(ctx, "GetDecisionMultiResource")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk, as.cache, as.config.AllowDirectEntitlements)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToInitPDP, err))
	}
	request := req.Msg
	entityIdentifier := request.GetEntityIdentifier()
	action := request.GetAction()
	resources := request.GetResources()
	fulfillableObligations := request.GetFulfillableObligationFqns()

	reqContext, err := as.getDecisionRequestContext(ctx)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, err)
	}

	decision, err := pdp.GetDecision(
		ctx,
		entityIdentifier,
		action,
		resources,
		reqContext,
		fulfillableObligations,
	)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToGetDecision, err))
	}

	resourceDecisions, err := rollupResourceDecisions(decision)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, err)
	}

	resp := &authzV2.GetDecisionMultiResourceResponse{
		AllPermitted: &wrapperspb.BoolValue{
			Value: decision.AllPermitted,
		},
		ResourceDecisions: resourceDecisions,
	}

	return connect.NewResponse(resp), nil
}

// GetDecisionBulk for multiple requests, each comprising a combination of entity chain, action, and one or more resources
func (as *Service) GetDecisionBulk(ctx context.Context, req *connect.Request[authzV2.GetDecisionBulkRequest]) (*connect.Response[authzV2.GetDecisionBulkResponse], error) {
	as.logger.DebugContext(ctx, "getting decision bulk")

	ctx, span := as.Start(ctx, "GetDecisionBulk")
	defer span.End()

	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk, as.cache, as.config.AllowDirectEntitlements)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToInitPDP, err))
	}

	multiRequests := req.Msg.GetDecisionRequests()
	decisionResponses := make([]*authzV2.GetDecisionMultiResourceResponse, len(multiRequests))

	reqContext, err := as.getDecisionRequestContext(ctx)
	if err != nil {
		return nil, statusifyError(ctx, as.logger, err)
	}

	// TODO: revisit performance of this loop after introduction of caching and registered resource values within decisioning,
	// as the same entity in multiple requests should only be resolved JIT once, not once per request if the same in each.
	for idx, request := range multiRequests {
		entityIdentifier := request.GetEntityIdentifier()
		action := request.GetAction()
		resources := request.GetResources()
		fulfillableObligations := request.GetFulfillableObligationFqns()

		decision, err := pdp.GetDecision(ctx, entityIdentifier, action, resources, reqContext, fulfillableObligations)
		if err != nil {
			return nil, statusifyError(ctx, as.logger, errors.Join(ErrFailedToGetDecision, err))
		}

		resourceDecisions, err := rollupResourceDecisions(decision)
		if err != nil {
			return nil, statusifyError(ctx, as.logger, err, slog.Int("index", idx))
		}

		decisionResponse := &authzV2.GetDecisionMultiResourceResponse{
			AllPermitted: &wrapperspb.BoolValue{
				Value: decision.AllPermitted,
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

// Builds a decision request context out of contextual metadata for the downstream obligation trigger/fulfillment decisioning
func (as *Service) getDecisionRequestContext(ctx context.Context) (*policy.RequestContext, error) {
	incoming := true
	clientID, err := ctxAuth.GetClientIDFromContext(ctx, incoming)
	if err != nil {
		return nil, errors.Join(ErrFailedToBuildRequestContext, err)
	}
	return &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: clientID,
		},
	}, nil
}
