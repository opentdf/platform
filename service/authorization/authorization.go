package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/creasty/defaults"
	"github.com/go-playground/validator/v10"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/rego"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/access"
	"github.com/opentdf/platform/service/internal/entitlements"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/logger/audit"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policies"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type AuthorizationService struct { //nolint:revive // AuthorizationService is a valid name for this struct
	authorization.UnimplementedAuthorizationServiceServer
	sdk         *otdf.SDK
	config      Config
	logger      *logger.Logger
	tokenSource *oauth2.TokenSource
	eval        rego.PreparedEvalQuery
}

type Config struct {
	// Entity Resolution Service URL
	ERSURL string `mapstructure:"ersurl" validate:"required,http_url"`
	// OAuth Client ID
	ClientID string `mapstructure:"clientid" validate:"required"`
	// OAuth Client secret
	ClientSecret string `mapstructure:"clientsecret" validate:"required"`
	// OAuth token endpoint
	TokenEndpoint string `mapstructure:"tokenendpoint" validate:"required,http_url"`
	// Custom Rego Policy To Load
	Rego CustomRego `mapstructure:"rego"`
}

type CustomRego struct {
	// Path to Rego file
	Path string `mapstructure:"path"`
	// Rego Query
	Query string `mapstructure:"query" default:"data.opentdf.entitlements.attributes"`
}

const tokenExpiryDelay = 100

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "authorization",
		ServiceDesc: &authorization.AuthorizationService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			var (
				err             error
				entitlementRego []byte
				authZCfg        = new(Config)
			)

			logger := srp.Logger

			// default ERS endpoint
			as := &AuthorizationService{sdk: srp.SDK, logger: logger}
			if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
				logger.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
			}

			if err := defaults.Set(authZCfg); err != nil {
				panic(fmt.Errorf("failed to set defaults for authorization service config: %w", err))
			}

			if err := mapstructure.Decode(srp.Config.ExtraProps, &authZCfg); err != nil {
				panic(fmt.Errorf("invalid auth svc cfg [%v] %w", srp.Config.ExtraProps, err))
			}

			// Validate Config
			validate := validator.New(validator.WithRequiredStructEnabled())
			if err := validate.Struct(authZCfg); err != nil {
				var invalidValidationError *validator.InvalidValidationError
				if errors.As(err, &invalidValidationError) {
					logger.Error("error validating authorization service config", slog.String("error", err.Error()))
					panic(fmt.Errorf("error validating authorization service config: %w", err))
				}

				var validationErrors validator.ValidationErrors
				if errors.As(err, &validationErrors) {
					for _, err := range validationErrors {
						logger.Error("error validating authorization service config", slog.String("error", err.Error()))
						panic(fmt.Errorf("error validating authorization service config: %w", err))
					}
				}
			}

			logger.Debug("authorization service config", slog.Any("config", authZCfg))

			// Build Rego PreparedEvalQuery

			// Load rego from embedded file or custom path
			if authZCfg.Rego.Path != "" {
				entitlementRego, err = os.ReadFile(authZCfg.Rego.Path)
				if err != nil {
					panic(fmt.Errorf("failed to read custom entitlements.rego file: %w", err))
				}
			} else {
				entitlementRego, err = policies.EntitlementsRego.ReadFile("entitlements/entitlements.rego")
				if err != nil {
					panic(fmt.Errorf("failed to read entitlements.rego file: %w", err))
				}
			}

			// Register builtin
			subjectmappingbuiltin.SubjectMappingBuiltin()

			as.eval, err = rego.New(
				rego.Query(authZCfg.Rego.Query),
				rego.Module("entitlements.rego", string(entitlementRego)),
				rego.StrictBuiltinErrors(true),
			).PrepareForEval(context.Background())
			if err != nil {
				panic(fmt.Errorf("failed to prepare entitlements.rego for eval: %w", err))
			}

			clientCredsConfig := clientcredentials.Config{ClientID: authZCfg.ClientID, ClientSecret: authZCfg.ClientSecret, TokenURL: authZCfg.TokenEndpoint}
			newTokenSource := oauth2.ReuseTokenSourceWithExpiry(nil, clientCredsConfig.TokenSource(context.Background()), tokenExpiryDelay)

			as.config = *authZCfg
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
	as.logger.DebugContext(ctx, "checking readiness of authorization service")
	return nil
}

// abstracted into variable for mocking in tests
var retrieveEntitlements = func(ctx context.Context, req *authorization.GetEntitlementsRequest, as *AuthorizationService) (*authorization.GetEntitlementsResponse, error) {
	return as.GetEntitlements(ctx, req)
}

// abstracted into variable for mocking in tests
var executeRego = func(ctx context.Context, pq rego.PreparedEvalQuery, options ...rego.EvalOption) (rego.ResultSet, error) {
	return pq.Eval(ctx, options...)
}

func (as *AuthorizationService) GetDecisionsByToken(ctx context.Context, req *authorization.GetDecisionsByTokenRequest) (*authorization.GetDecisionsByTokenResponse, error) {
	var decisionsRequests = []*authorization.DecisionRequest{}
	// for each token decision request
	for _, tdr := range req.GetDecisionRequests() {
		ecResp, err := as.sdk.EntityResoution.CreateEntityChainFromJwt(ctx, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: tdr.GetTokens()})
		if err != nil {
			as.logger.Error("Error calling ERS to get entity chains from jwts")
			return nil, err
		}

		// form a decision request for the token decision request
		decisionsRequests = append(decisionsRequests, &authorization.DecisionRequest{
			Actions:            tdr.GetActions(),
			EntityChains:       ecResp.GetEntityChains(),
			ResourceAttributes: tdr.GetResourceAttributes(),
		})
	}

	resp, err := as.GetDecisions(ctx, &authorization.GetDecisionsRequest{
		DecisionRequests: decisionsRequests,
	})

	if err != nil {
		return nil, err
	}
	return &authorization.GetDecisionsByTokenResponse{DecisionResponses: resp.GetDecisionResponses()}, err
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
				// if attribute an FQN does not exist
				// return deny for all entity chains aginst this RA set and continue to next
				if errors.Is(err, db.StatusifyError(db.ErrNotFound, "")) {
					for _, ec := range dr.GetEntityChains() {
						decisionResp := &authorization.DecisionResponse{
							Decision:      authorization.DecisionResponse_DECISION_DENY,
							EntityChainId: ec.GetId(),
							Action: &policy.Action{
								Value: &policy.Action_Standard{
									Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
								},
							},
						}
						if ra.GetResourceAttributesId() != "" {
							decisionResp.ResourceAttributesId = ra.GetResourceAttributesId()
						} else if len(ra.GetAttributeValueFqns()) > 0 {
							decisionResp.ResourceAttributesId = ra.GetAttributeValueFqns()[0]
						}
						rsp.DecisionResponses = append(rsp.DecisionResponses, decisionResp)
					}
					continue
				}
				return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("fqns", strings.Join(ra.GetAttributeValueFqns(), ", ")))
			}
			var attrDefs []*policy.Attribute
			var attrVals []*policy.Value
			var fqns []string
			for fqn, v := range dataAttrDefsAndVals {
				attrDefs = append(attrDefs, v.GetAttribute())
				attrVal := v.GetValue()
				fqns = append(fqns, fqn)
				attrVal.Fqn = fqn
				attrVals = append(attrVals, attrVal)
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

				auditECEntitlements := make([]audit.EntityChainEntitlement, 0)
				auditEntityDecisions := make([]audit.EntityDecision, 0)
				entityAttrValues := make(map[string][]string)

				if len(entities) == 0 || len(allPertinentFqnsRA.GetAttributeValueFqns()) == 0 {
					as.logger.WarnContext(ctx, "Empty entity list and/or entity data attribute list")
				} else {
					ecEntitlements, err := retrieveEntitlements(ctx, &req, as)
					if err != nil {
						// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
						return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("extra", "getEntitlements request failed"))
					}

					// TODO this might cause errors if multiple entities dont have ids
					// currently just adding each entity returned to same list
					for _, e := range ecEntitlements.GetEntitlements() {
						auditECEntitlements = append(auditECEntitlements, audit.EntityChainEntitlement{
							EntityID:                 e.GetEntityId(),
							AttributeValueReferences: e.GetAttributeValueFqns(),
						})
						entityAttrValues[e.GetEntityId()] = e.GetAttributeValueFqns()
					}
				}

				// call access-pdp
				accessPDP := access.NewPdp(as.logger)
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
				for entityID, d := range decisions {
					// Set overall decision as well as individual entity decision
					entityDecision := authorization.DecisionResponse_DECISION_PERMIT
					if !d.Access {
						entityDecision = authorization.DecisionResponse_DECISION_DENY
						decision = authorization.DecisionResponse_DECISION_DENY
					}

					// Add entity decision to audit list
					entityEntitlementFqns := entityAttrValues[entityID]
					if entityEntitlementFqns == nil {
						entityEntitlementFqns = []string{}
					}
					auditEntityDecisions = append(auditEntityDecisions, audit.EntityDecision{
						EntityID:     entityID,
						Decision:     entityDecision.String(),
						Entitlements: entityEntitlementFqns,
					})
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
				if ra.GetResourceAttributesId() != "" {
					decisionResp.ResourceAttributesId = ra.GetResourceAttributesId()
				} else if len(ra.GetAttributeValueFqns()) > 0 {
					decisionResp.ResourceAttributesId = ra.GetAttributeValueFqns()[0]
				}

				auditDecision := audit.GetDecisionResultDeny
				if decision == authorization.DecisionResponse_DECISION_PERMIT {
					auditDecision = audit.GetDecisionResultPermit
				}
				as.logger.Audit.GetDecision(ctx, audit.GetDecisionEventParams{
					Decision:                auditDecision,
					EntityChainEntitlements: auditECEntitlements,
					EntityChainID:           decisionResp.GetEntityChainId(),
					EntityDecisions:         auditEntityDecisions,
					FQNs:                    fqns,
					ResourceAttributeID:     decisionResp.GetResourceAttributesId(),
				})
				rsp.DecisionResponses = append(rsp.DecisionResponses, decisionResp)
			}
		}
	}
	return rsp, nil
}

func (as *AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	as.logger.DebugContext(ctx, "getting entitlements")
	request := attr.GetAttributeValuesByFqnsRequest{
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	}
	// Lack of scope has impacts on performance
	// https://github.com/opentdf/platform/issues/365
	if req.GetScope() == nil {
		// TODO: Reomve and use MatchSubjectMappings instead later in the flow
		listAttributeResp, err := as.sdk.Attributes.ListAttributes(ctx, &attr.ListAttributesRequest{})
		if err != nil {
			as.logger.ErrorContext(ctx, "failed to list attributes", slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "failed to list attributes")
		}
		var attributeFqns []string
		for _, attr := range listAttributeResp.GetAttributes() {
			for _, val := range attr.GetValues() {
				attributeFqns = append(attributeFqns, val.GetFqn())
			}
		}
		request.Fqns = attributeFqns
	} else {
		// get subject mappings
		request.Fqns = req.GetScope().GetAttributeValueFqns()
	}
	avf, err := as.sdk.Attributes.GetAttributeValuesByFqns(ctx, &request)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to get attribute values by fqns", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to get attribute values by fqns")
	}
	subjectMappings := avf.GetFqnAttributeValues()
	as.logger.DebugContext(ctx, "retrieved from subject mappings service", slog.Any("subject_mappings: ", subjectMappings))
	// TODO: this could probably be moved to proto validation https://github.com/opentdf/platform/issues/1057
	if req.Entities == nil {
		as.logger.ErrorContext(ctx, "requires entities")
		return nil, status.Error(codes.InvalidArgument, "requires entities")
	}
	rsp := &authorization.GetEntitlementsResponse{
		Entitlements: make([]*authorization.EntityEntitlements, len(req.GetEntities())),
	}
	for idx, entity := range req.GetEntities() {
		// TODO: change this and the opa to take a bulk request and not have to call opa for each entity
		// get the client auth token
		authToken, err := (*as.tokenSource).Token()
		if err != nil {
			as.logger.ErrorContext(ctx, "failed to get client auth token in GetEntitlements", slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "failed to get client auth token in GetEntitlements")
		}

		in, err := entitlements.OpaInput(entity, subjectMappings, as.config.ERSURL, authToken.AccessToken)
		if err != nil {
			as.logger.ErrorContext(ctx, "failed to build rego input", slog.Any("entity", entity), slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "failed to build rego input")
		}
		as.logger.DebugContext(ctx, "entitlements", "entity_id", entity.GetId(), "input", fmt.Sprintf("%+v", in))

		results, err := executeRego(ctx, as.eval, rego.EvalInput(in))
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to evaluate entitlements policy")
		}

		// If we get no results and no error then we assume that the entity is not entitled to anything
		if len(results) == 0 {
			as.logger.DebugContext(ctx, "no entitlement results", slog.String("entity_id", entity.GetId()))
			return rsp, nil
		}

		// I am not sure how we would end up with multiple results but lets return an empty entitlement set for now
		if len(results) > 1 {
			as.logger.WarnContext(ctx, "multiple entitlement results", slog.String("entity_id", entity.GetId()), slog.String("results", fmt.Sprintf("%+v", results)))
			return rsp, nil
		}

		// If we get no expressions then we assume that the entity is not entitled to anything
		if len(results[0].Expressions) == 0 {
			as.logger.WarnContext(ctx, "no entitlement expressions", slog.String("entity_id", entity.GetId()), slog.String("results", fmt.Sprintf("%+v", results)))
			return rsp, nil
		}

		// Check to maksure if the value is a list. Good validation if someone customizes the rego policy
		resultsEntitlements, valueListOk := results[0].Expressions[0].Value.([]interface{})
		if !valueListOk {
			as.logger.ErrorContext(ctx, "entitlements is not an array", slog.String("entity_id", entity.GetId()), slog.String("value", fmt.Sprintf("%+v", resultsEntitlements...)))
			return rsp, nil
		}
		as.logger.DebugContext(ctx, "opa results", "entity_id", entity.GetId(), "results", fmt.Sprintf("%+v", results))
		// map for attributes for optional comprehensive
		attributesMap := make(map[string]*policy.Attribute)
		// Build array with length of results
		var entitlements = make([]string, len(resultsEntitlements))

		// Build entitlements list
		for valueIDX, value := range resultsEntitlements {
			entitlement, valueOK := value.(string)
			// If value is not okay skip adding to entitlements
			if !valueOK {
				as.logger.WarnContext(ctx, "issue with adding entitlement", slog.String("entity_id", entity.GetId()), slog.String("entitlement", entitlement))
				continue
			}
			// if comprehensive and a hierarchy attribute is entitled then add the lower entitlements
			if req.GetWithComprehensiveHierarchy() {
				entitlements = getComprehensiveHierarchy(attributesMap, avf, entitlement, as, entitlements)
			}
			// Add entitlement to entitlements array
			entitlements[valueIDX] = entitlement
		}
		// Update the entity with its entitlements
		rsp.Entitlements[idx] = &authorization.EntityEntitlements{
			EntityId:           entity.GetId(),
			AttributeValueFqns: entitlements,
		}
	}

	return rsp, nil
}

func retrieveAttributeDefinitions(ctx context.Context, ra *authorization.ResourceAttribute, sdk *otdf.SDK) (map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
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

func getComprehensiveHierarchy(attributesMap map[string]*policy.Attribute, avf *attr.GetAttributeValuesByFqnsResponse, entitlement string, as *AuthorizationService, entitlements []string) []string {
	// load attributesMap
	if len(attributesMap) == 0 {
		// Go through all attribute definitions
		attrDefs := avf.GetFqnAttributeValues()
		for _, attrDef := range attrDefs {
			for _, attrVal := range attrDef.GetAttribute().GetValues() {
				attributesMap[attrVal.GetFqn()] = attrDef.GetAttribute()
			}
		}
	}
	attrDef := attributesMap[entitlement]
	if attrDef == nil {
		as.logger.Warn("no attribute definition found for entity", "fqn", entitlement)
		return entitlements
	}
	if attrDef.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		// add the following fqn in the hierarchy
		isFollowing := false
		for _, followingAttrVal := range attrDef.GetValues() {
			if isFollowing {
				entitlements = append(entitlements, followingAttrVal.GetFqn())
			} else {
				// if fqn match, then rest are added
				// order is determined by creation order
				// creation order is guaranteed unless unsafe operations used
				isFollowing = followingAttrVal.GetFqn() == entitlement
			}
		}
	}
	return entitlements
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
