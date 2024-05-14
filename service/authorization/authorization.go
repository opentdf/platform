package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/profiler"
	opaSdk "github.com/open-policy-agent/opa/sdk"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/access"
	"github.com/opentdf/platform/service/internal/entitlements"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type AuthorizationService struct { //nolint:revive // AuthorizationService is a valid name for this struct
	authorization.UnimplementedAuthorizationServiceServer
	eng         *opa.Engine
	sdk         *otdf.SDK
	ersURL      string
	logger      *logger.Logger
	tokenSource *oauth2.TokenSource
}

const tokenExpiryDelay = 100

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "authorization",
		ServiceDesc: &authorization.AuthorizationService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			// default ERS endpoint
			var ersURL = "http://localhost:8080/entityresolution/resolve"
			var clientID = "tdf-authorization-svc"
			var clientSecert = "secret"
			var tokenEndpoint = "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token" //nolint:gosec // default token endpoint

			as := &AuthorizationService{eng: srp.Engine, sdk: srp.SDK, logger: srp.Logger}
			if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
				slog.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
			}

			// if its passed in the config use that
			val, ok := srp.Config.ExtraProps["ersUrl"]
			if ok {
				ersURL, ok = val.(string)
				if !ok {
					panic("Error casting ersURL to string")
				}
			}
			val, ok = srp.Config.ExtraProps["clientId"]
			if ok {
				clientID, ok = val.(string)
				if !ok {
					panic("Error casting clientID to string")
				}
			}
			val, ok = srp.Config.ExtraProps["clientSecert"]
			if ok {
				clientSecert, ok = val.(string)
				if !ok {
					panic("Error casting clientSecert to string")
				}
			}
			val, ok = srp.Config.ExtraProps["tokenEndpoint"]
			if ok {
				tokenEndpoint, ok = val.(string)
				if !ok {
					panic("Error casting tokenEndpoint to string")
				}
			}
			config := clientcredentials.Config{ClientID: clientID, ClientSecret: clientSecert, TokenURL: tokenEndpoint}
			newTokenSource := oauth2.ReuseTokenSourceWithExpiry(nil, config.TokenSource(context.Background()), tokenExpiryDelay)

			as.ersURL = ersURL
			as.tokenSource = &newTokenSource

			return as, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				authServer, okAuth := server.(authorization.AuthorizationServiceServer)
				if !okAuth {
					return fmt.Errorf("failed to assert server type to authorization.AuthorizationServiceServer")
				}
				return authorization.RegisterAuthorizationServiceHandlerServer(ctx, mux, authServer)
			}
		},
	}
}

// TODO: Not sure what we want to check here?
func (as AuthorizationService) IsReady(ctx context.Context) error {
	slog.DebugContext(ctx, "checking readiness of authorization service")
	return nil
}

// abstracted into variable for mocking in tests
var retrieveAttributeDefinitions = func(ctx context.Context, ra *authorization.ResourceAttribute, sdk *otdf.SDK) (map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	attrFqns := ra.GetAttributeValueFqns()
	if len(attrFqns) == 0 {
		return make(map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue), nil
	}
	resp, err := sdk.Attributes.GetAttributeValuesByFqns(ctx, &attr.GetAttributeValuesByFqnsRequest{
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: false,
		},
		Fqns: attrFqns,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetFqnAttributeValues(), nil
}

// abstracted into variable for mocking in tests
var retrieveEntitlements = func(ctx context.Context, req *authorization.GetEntitlementsRequest, as *AuthorizationService) (*authorization.GetEntitlementsResponse, error) {
	return as.GetEntitlements(ctx, req)
}

func (as *AuthorizationService) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest) (*authorization.GetDecisionsResponse, error) {
	as.logger.DebugContext(ctx, "getting decisions")

	// Temporary canned echo response with permit decision for all requested decision/entity/ra combos
	rsp := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 0),
	}
	for _, dr := range req.GetDecisionRequests() {
		for _, ra := range dr.GetResourceAttributes() {
			as.logger.DebugContext(ctx, "getting resource attributes", slog.String("FQNs", strings.Join(ra.GetAttributeValueFqns(), ", ")))

			// get attribute definition/value combinations
			dataAttrDefsAndVals, err := retrieveAttributeDefinitions(ctx, ra, as.sdk)
			if err != nil {
				// TODO: should all decisions in a request fail if one FQN lookup fails?
				return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("fqns", strings.Join(ra.GetAttributeValueFqns(), ", ")))
			}
			var attrDefs []*policy.Attribute
			var attrVals []*policy.Value
			for _, v := range dataAttrDefsAndVals {
				attrDefs = append(attrDefs, v.GetAttribute())
				attrVals = append(attrVals, v.GetValue())
			}

			attrDefs, err = populateAttrDefValueFqns(attrDefs)
			if err != nil {
				return nil, err
			}

			// get the relevant resource attribute fqns
			allPertinentFqnsRA := authorization.ResourceAttribute{
				AttributeValueFqns: ra.GetAttributeValueFqns(),
			}
			for _, attrDef := range attrDefs {
				if attrDef.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
					for _, value := range attrDef.GetValues() {
						allPertinentFqnsRA.AttributeValueFqns = append(allPertinentFqnsRA.AttributeValueFqns, value.GetFqn())
					}
				}
			}

			for _, ec := range dr.GetEntityChains() {
				//
				// TODO: we should already have the subject mappings here and be able to just use OPA to trim down the known data attr values to the ones matched up with the entities
				//
				entities := ec.GetEntities()
				req := authorization.GetEntitlementsRequest{
					Entities: entities,
					Scope:    &allPertinentFqnsRA,
				}
				entityAttrValues := make(map[string][]string)
				if len(entities) == 0 || len(allPertinentFqnsRA.GetAttributeValueFqns()) == 0 {
					slog.WarnContext(ctx, "Empty entity list and/or entity data attribute list")
				} else {
					ecEntitlements, err := retrieveEntitlements(ctx, &req, as)
					if err != nil {
						// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
						return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("extra", "getEntitlements request failed"))
					}

					// currently just adding each entity returned to same list
					for _, e := range ecEntitlements.GetEntitlements() {
						entityAttrValues[e.GetEntityId()] = e.GetAttributeValueFqns()
					}
				}

				// call access-pdp
				accessPDP := access.NewPdp()
				decisions, err := accessPDP.DetermineAccess(
					ctx,
					attrVals,
					entityAttrValues,
					attrDefs,
				)
				if err != nil {
					// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
					return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("extra", "DetermineAccess request to Access PDP failed"))
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
					EntityChainId: ec.GetId(),
					Action: &policy.Action{
						Value: &policy.Action_Standard{
							Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
						},
					},
				}
				if len(ra.GetAttributeValueFqns()) > 0 {
					decisionResp.ResourceAttributesId = ra.GetAttributeValueFqns()[0]
				}
				rsp.DecisionResponses = append(rsp.DecisionResponses, decisionResp)
			}
		}
	}
	return rsp, nil
}

func (as *AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	as.logger.DebugContext(ctx, "getting entitlements")
	// Scope is required for because of performance.  Remove and handle 360 no scope
	// https://github.com/opentdf/platform/issues/365
	if req.GetScope() == nil {
		as.logger.ErrorContext(ctx, "requires scope")
		return nil, errors.New(db.ErrTextFqnMissingValue)
	}
	// get subject mappings
	request := attr.GetAttributeValuesByFqnsRequest{
		Fqns: req.GetScope().GetAttributeValueFqns(),
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	}
	avf, err := as.sdk.Attributes.GetAttributeValuesByFqns(ctx, &request)
	if err != nil {
		return nil, err
	}
	subjectMappings := avf.GetFqnAttributeValues()
	as.logger.DebugContext(ctx, "retrieved from subject mappings service", slog.Any("subject_mappings: ", subjectMappings))
	if req.Entities == nil {
		as.logger.ErrorContext(ctx, "requires entities")
		return nil, errors.New("entity chain is required")
	}
	rsp := &authorization.GetEntitlementsResponse{
		Entitlements: make([]*authorization.EntityEntitlements, len(req.GetEntities())),
	}
	for i, entity := range req.GetEntities() {
		// get the client auth token
		authToken, err := (*as.tokenSource).Token()
		if err != nil {
			return nil, err
		}
		// OPA
		in, err := entitlements.OpaInput(entity, subjectMappings, as.ersURL, authToken.AccessToken)
		if err != nil {
			return nil, err
		}
		as.logger.DebugContext(ctx, "entitlements", "entity_id", entity.GetId(), "input", fmt.Sprintf("%+v", in))
		// uncomment for debugging
		// if slog.Default().Enabled(ctx, slog.LevelDebug) {
		//	_ = json.NewEncoder(os.Stdout).Encode(in)
		// }
		options := opaSdk.DecisionOptions{
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
		// uncomment for debugging
		// if slog.Default().Enabled(ctx, slog.LevelDebug) {
		//	_ = json.NewEncoder(os.Stdout).Encode(decision.Result)
		// }
		results, ok := decision.Result.([]interface{})
		if !ok {
			as.logger.DebugContext(ctx, "not ok", "entity_id", entity.GetId(), "decision.Result", fmt.Sprintf("%+v", decision.Result))
			return nil, err
		}
		as.logger.DebugContext(ctx, "opa results", "entity_id", entity.GetId(), "results", fmt.Sprintf("%+v", results))
		saa := make([]string, len(results))
		for k, v := range results {
			str, okk := v.(string)
			if !okk {
				as.logger.DebugContext(ctx, "not ok", slog.String("entity_id", entity.GetId()), slog.String(strconv.Itoa(k), fmt.Sprintf("%+v", v)))
			}
			saa[k] = str
		}
		rsp.Entitlements[i] = &authorization.EntityEntitlements{
			EntityId:           entity.GetId(),
			AttributeValueFqns: saa,
		}
	}
	as.logger.DebugContext(ctx, "opa", "rsp", fmt.Sprintf("%+v", rsp))
	return rsp, nil
}

// Build an fqn from a namespace, attribute name, and value
func fqnBuilder(n string, a string, v string) (string, error) {
	fqn := "https://"
	switch {
	case n != "" && a != "" && v != "":
		return fqn + n + "/attr/" + a + "/value/" + v, nil
	case n != "" && a != "" && v == "":
		return fqn + n + "/attr/" + a, nil
	case n != "" && a == "":
		return fqn + n, nil
	default:
		return "", errors.New("invalid FQN, unable to build fqn")
	}
}

// If there are missing fqns in the attribute definition fill them in using
// information from the attr definition
func populateAttrDefValueFqns(attrDefs []*policy.Attribute) ([]*policy.Attribute, error) {
	for i, attrDef := range attrDefs {
		ns := attrDef.GetNamespace().GetName()
		attr := attrDef.GetName()
		for j, value := range attrDef.GetValues() {
			if value.GetFqn() == "" {
				fqn, err := fqnBuilder(ns, attr, value.GetValue())
				if err != nil {
					return nil, err
				}
				attrDefs[i].Values[j].Fqn = fqn
			}
		}
	}
	return attrDefs, nil
}
