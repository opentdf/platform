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
	"github.com/opentdf/platform/internal/access"
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

var RetrieveAttributeDefinitions = func(ctx context.Context, ra *authorization.ResourceAttribute, as AuthorizationService) (*attr.GetAttributeValuesByFqnsResponse, error) {
	return as.sdk.Attributes.GetAttributeValuesByFqns(ctx, &attr.GetAttributeValuesByFqnsRequest{
		Fqns: ra.AttributeFqns,
	})
}

var RetrieveEntitlements = func(ctx context.Context, req *authorization.GetEntitlementsRequest, as AuthorizationService) (*authorization.GetEntitlementsResponse, error) {
	return as.GetEntitlements(ctx, req)
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

			// get attribute definisions
			getAttrsRes, err := RetrieveAttributeDefinitions(ctx, ra, as)
			if err != nil {
				// TODO: should all decisions in a request fail if one FQN lookup fails?
				return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("fqns", strings.Join(ra.AttributeFqns, ", ")))
			}
			// get list of attributes from response
			var attrDefs []*policy.Attribute
			for _, v := range getAttrsRes.GetFqnAttributeValues() {
				attrDefs = append(attrDefs, v.GetAttribute())
			}

			// format resource fqns as attribute instances for accesspdp
			var dataAttrs []access.AttributeInstance
			for _, x := range ra.AttributeFqns {
				inst, err := access.ParseInstanceFromURI(x)
				if err != nil {
					// TODO: should all decisions in a request fail if one FQDN to attributeinstance conversion fails?
					return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("attribute instance conversion failed for resource fqn ", x))
				}
				dataAttrs = append(dataAttrs, inst)
			}

			for _, ec := range dr.EntityChains {
				// fmt.Printf("\nTODO: make access decision here with these fully qualified attributes: %+v\n", attrs)
				// get the entities entitlements
				entities := ec.GetEntities()
				req := authorization.GetEntitlementsRequest{Entities: entities}
				ecEntitlements, err := RetrieveEntitlements(ctx, &req, as)
				if err != nil {
					// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
					return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("getEntitlements request failed ", req.String()))
				}

				// format subject fqns as attribute instances for accesspdp
				entityAttrs := make(map[string][]access.AttributeInstance)
				for _, e := range ecEntitlements.Entitlements {
					// currently just adding each entity retuned to same list
					var thisEntityAttrs []access.AttributeInstance
					for _, x := range e.GetAttributeId() {
						inst, err := access.ParseInstanceFromURI(x)
						if err != nil {
							// TODO: should all decisions in a request fail if one FQDN to attributeinstance conversion fails?
							return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("attribute instance conversion failed for subject fqn ", x))
						}
						thisEntityAttrs = append(thisEntityAttrs, inst)
					}
					entityAttrs[e.EntityId] = thisEntityAttrs
				}

				// call access-pdp
				accessPDP := access.NewPdp()
				decisions, err := accessPDP.DetermineAccess(
					ctx,
					dataAttrs,
					entityAttrs,
					attrDefs,
				)
				if err != nil {
					// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
					return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("determinsAccess request to accesspdp failed", ""))
				}
				// check the decisions
				decision := authorization.DecisionResponse_DECISION_PERMIT
				for _, d := range decisions {
					if !d.Access {
						decision = authorization.DecisionResponse_DECISION_DENY
					}
				}

				decisionResp := &authorization.DecisionResponse{
					Decision:      decision,
					EntityChainId: ec.Id,
					Action: &policy.Action{
						Value: &policy.Action_Standard{
							Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
						},
					},
					ResourceAttributesId: "resourceAttributesId_stub" + ra.String(),
				}
				rsp.DecisionResponses = append(rsp.DecisionResponses, decisionResp)
			}
		}
	}
	return rsp, nil
}

func (as AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	slog.Debug("getting entitlements")
	// get subject mappings
	// smc := subjectmapping.NewSubjectMappingServiceClient(as.cc)
	subjectSets := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalField:  "Department",
							Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
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
