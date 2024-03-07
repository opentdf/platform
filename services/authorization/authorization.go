package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
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

			attrs, err := as.sdk.Attributes.GetAttributesByValueFqns(ctx, &attr.GetAttributesByValueFqnsRequest{
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
					Action: &authorization.Action{
						Value: &authorization.Action_Standard{
							Standard: authorization.Action_STANDARD_ACTION_TRANSMIT,
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
	// smc := subjectmapping.NewSubjectMappingServiceClient(as.cc)
	subjectSets := []*subjectmapping.SubjectSet{
		{
			ConditionGroups: []*subjectmapping.ConditionGroup{
				{
					Conditions: []*subjectmapping.Condition{
						{
							SubjectExternalField:  "Department",
							Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues: []string{"Marketing", "Sales"},
						},
					},
				},
			},
		},
	}

	slog.InfoContext(ctx, "retrieved from subject mappings service", slog.Any("subjectSets: ", subjectSets))
	// OPA
	in, err := entitlements.OpaInput(req.Entities[0], subjectSets[0])
	if err != nil {
		return nil, err
	}
	slog.Debug("entitlements", "input", fmt.Sprintf("%+v", in))
	if err := json.NewEncoder(os.Stdout).Encode(in); err != nil {
		panic(err)
	}
	options := sdk.DecisionOptions{
		Now:                 time.Now(),
		Path:                "opentdf/entitlements/entitlements",
		Input:               in,
		NDBCache:            nil,
		StrictBuiltinErrors: false,
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
	slog.DebugContext(ctx, "opa", "result", fmt.Sprintf("%+v", decision.Result))
	results, ok := decision.Result.(map[string]interface{})
	if !ok {
		slog.DebugContext(ctx, "not ok", "decision.Result", fmt.Sprintf("%+v", decision.Result))
		return nil, err
	}
	rsp := &authorization.GetEntitlementsResponse{
		Entitlements: make([]*authorization.EntityEntitlements, 0),
	}
	for k, v := range results {
		va, okk := v.([]interface{})
		if !okk {
			slog.DebugContext(ctx, "not ok", k, fmt.Sprintf("%+v", v))
			continue
		}
		var saa []string
		for _, sv := range va {
			str, okkk := sv.(string)
			if !okkk {
				slog.DebugContext(ctx, "not ok", k, fmt.Sprintf("%+v", sv))
			}
			saa = append(saa, str)
		}
		slog.DebugContext(ctx, "opa", k, fmt.Sprintf("%+v", va))
		rsp.Entitlements = append(rsp.Entitlements, &authorization.EntityEntitlements{
			EntityId:    k,
			AttributeId: saa,
		})
		slog.DebugContext(ctx, "opa", "rsp", fmt.Sprintf("%+v", rsp))
	}
	return rsp, nil
}
