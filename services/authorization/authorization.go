package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/profiler"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/opentdf/platform/internal/entitlements"
	"github.com/opentdf/platform/internal/opa"
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/services"
)

type AuthorizationService struct {
	authorization.UnimplementedAuthorizationServiceServer
	eng *opa.Engine
	sdk *otdf.SDK
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "authorization",
		ServiceDesc: &authorization.AuthorizationService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &AuthorizationService{eng: srp.Engine, sdk: srp.SDK}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				return authorization.RegisterAuthorizationServiceHandlerServer(ctx, mux, server.(authorization.AuthorizationServiceServer))
			}
		},
	}
}

func (as AuthorizationService) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest) (*authorization.GetDecisionsResponse, error) {
	slog.DebugContext(ctx, "getting decisions")

	// Temporary canned echo response with permit decision for all requested decision/entity/ra combos
	rsp := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 0),
	}
	for _, dr := range req.DecisionRequests {
		for _, ra := range dr.ResourceAttributes {
			slog.Debug("getting resource attributes", slog.String("FQNs", strings.Join(ra.AttributeFqns, ", ")))

			attrs, err := as.sdk.Attributes.GetAttributeValuesByFqns(ctx, &attr.GetAttributeValuesByFqnsRequest{
				Fqns: ra.AttributeFqns,
			})
			if err != nil {
				// TODO: should all decisions in a request fail if one FQN lookup fails?
				return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("fqns", strings.Join(ra.AttributeFqns, ", ")))
			}
			for _, ec := range dr.EntityChains {
				fmt.Printf("\nTODO: make access decision here with these fully qualified attributes: %+v\n", attrs)
				decision := &authorization.DecisionResponse{
					Decision:      authorization.DecisionResponse_DECISION_PERMIT,
					EntityChainId: ec.Id,
					Action: &policy.Action{
						Value: &policy.Action_Standard{
							Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
						},
					},
					ResourceAttributesId: "resourceAttributesId_stub" + ra.String(),
				}
				rsp.DecisionResponses = append(rsp.DecisionResponses, decision)
			}
		}
	}
	return rsp, nil
}

func (as AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	slog.Debug("getting entitlements")
	// get subject mappings
	request := attr.GetAttributeValuesByFqnsRequest{
		Fqns: req.Scope.AttributeFqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	}
	avf, err := as.sdk.Attributes.GetAttributeValuesByFqns(ctx, &request)
	if err != nil {
		return nil, err
	}
	subjectMappings := avf.GetFqnAttributeValues()
	slog.InfoContext(ctx, "retrieved from subject mappings service", slog.Any("subject_mappings: ", subjectMappings))
	// OPA
	in, err := entitlements.OpaInput(req.Entities[0], subjectMappings)
	if err != nil {
		return nil, err
	}
	slog.Debug("entitlements", "input", fmt.Sprintf("%+v", in))
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		_ = json.NewEncoder(os.Stdout).Encode(in)
	}
	options := sdk.DecisionOptions{
		Now:                 time.Now(),
		Path:                "opentdf/entitlements/attributes", // change to /resolve_entities to get output of idp_plugin
		Input:               in,
		NDBCache:            nil,
		StrictBuiltinErrors: true,
		Tracer:              nil,
		Metrics:             metrics.New(),
		Profiler:            profiler.New(),
		Instrument:          true,
		DecisionID:          fmt.Sprintf("%-v", req.String()),
	}
	decision, err := as.eng.Decision(ctx, options)
	if err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "opa", "result", fmt.Sprintf("%+v", decision.Result), "type", fmt.Sprintf("%T", decision.Result))
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		_ = json.NewEncoder(os.Stdout).Encode(decision.Result)
	}
	results, ok := decision.Result.([]interface{})
	if !ok {
		slog.DebugContext(ctx, "not ok", "decision.Result", fmt.Sprintf("%+v", decision.Result))
		return nil, err
	}
	rsp := &authorization.GetEntitlementsResponse{
		Entitlements: make([]*authorization.EntityEntitlements, len(req.Entities)),
	}
	slog.DebugContext(ctx, "opa results", "results", fmt.Sprintf("%+v", results))
	saa := make([]string, len(results))
	for k, v := range results {
		str, okk := v.(string)
		if !okk {
			slog.DebugContext(ctx, "not ok", slog.String(strconv.Itoa(k), fmt.Sprintf("%+v", v)))
		}
		saa[k] = str
	}
	// FIXME use index
	rsp.Entitlements[0] = &authorization.EntityEntitlements{
		EntityId:    req.Entities[0].Id,
		AttributeId: saa,
	}
	slog.DebugContext(ctx, "opa", "rsp", fmt.Sprintf("%+v", rsp))
	return rsp, nil
}
