package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
	"github.com/open-policy-agent/opa/rego"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/authorization/authorizationconnect"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdf "github.com/opentdf/platform/sdk"
	policies "github.com/opentdf/platform/service/authorization/policies"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/internal/access"
	"github.com/opentdf/platform/service/internal/entitlements"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrEmptyStringAttribute = errors.New("resource attributes must have at least one attribute value fqn")

type AuthorizationService struct { //nolint:revive // AuthorizationService is a valid name for this struct
	sdk    *otdf.SDK
	config *Config
	logger *logger.Logger
	eval   rego.PreparedEvalQuery
	trace.Tracer
}

type Config struct {
	// Custom Rego Policy To Load
	Rego CustomRego `mapstructure:"rego"`
}

type CustomRego struct {
	// Path to Rego file
	Path string `mapstructure:"path" json:"path"`
	// Rego Query
	Query string `mapstructure:"query" json:"query" default:"data.opentdf.entitlements.attributes"`
}

func OnConfigUpdate(as *AuthorizationService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		err := mapstructure.Decode(cfg, as.config)
		if err != nil {
			return fmt.Errorf("invalid auth svc cfg [%v] %w", cfg, err)
		}

		//nolint:contextcheck // context is not needed here
		if err = as.loadRegoAndBuiltins(as.config); err != nil {
			return fmt.Errorf("failed to load rego and builtins: %w", err)
		}

		as.logger.Info("authorization service config reloaded")

		return nil
	}
}

func NewRegistration() *serviceregistry.Service[authorizationconnect.AuthorizationServiceHandler] {
	as := new(AuthorizationService)
	onUpdateConfig := OnConfigUpdate(as)

	return &serviceregistry.Service[authorizationconnect.AuthorizationServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[authorizationconnect.AuthorizationServiceHandler]{
			Namespace:       "authorization",
			ServiceDesc:     &authorization.AuthorizationService_ServiceDesc,
			ConnectRPCFunc:  authorizationconnect.NewAuthorizationServiceHandler,
			GRPCGatewayFunc: authorization.RegisterAuthorizationServiceHandler,
			OnConfigUpdate:  onUpdateConfig,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (authorizationconnect.AuthorizationServiceHandler, serviceregistry.HandlerServer) {
				authZCfg := new(Config)

				logger := srp.Logger

				// default ERS endpoint
				as.sdk = srp.SDK
				as.logger = logger
				if err := srp.RegisterReadinessCheck("authorization", as.IsReady); err != nil {
					logger.Error("failed to register authorization readiness check", slog.String("error", err.Error()))
				}

				// Read in config defaults only on first register
				if err := defaults.Set(authZCfg); err != nil {
					panic(fmt.Errorf("failed to set defaults for authorization service config: %w", err))
				}

				// Only decode config if it exists
				if srp.Config != nil {
					if err := mapstructure.Decode(srp.Config, &authZCfg); err != nil {
						panic(fmt.Errorf("invalid auth svc cfg [%v] %w", srp.Config, err))
					}
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

				if err := as.loadRegoAndBuiltins(authZCfg); err != nil {
					logger.Error("failed to load rego and builtins", slog.String("error", err.Error()))
					panic(fmt.Errorf("failed to load rego and builtins: %w", err))
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

func (as *AuthorizationService) GetDecisionsByToken(ctx context.Context, req *connect.Request[authorization.GetDecisionsByTokenRequest]) (*connect.Response[authorization.GetDecisionsByTokenResponse], error) {
	// Extract trace context from the incoming request
	propagator := otel.GetTextMapPropagator()
	ctx = propagator.Extract(ctx, propagation.HeaderCarrier(req.Header()))

	ctx, span := as.Start(ctx, "GetDecisionsByToken")
	defer span.End()

	decisionsRequests := []*authorization.DecisionRequest{}

	// for each token decision request
	for _, tdr := range req.Msg.GetDecisionRequests() {
		ecResp, err := as.sdk.EntityResoution.CreateEntityChainFromJwt(ctx, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: tdr.GetTokens()})
		if err != nil {
			as.logger.ErrorContext(ctx, "error calling ERS to get entity chains from jwts")
			return nil, err
		}

		// form a decision request for the token decision request
		decisionsRequests = append(decisionsRequests, &authorization.DecisionRequest{
			Actions:            tdr.GetActions(),
			EntityChains:       ecResp.GetEntityChains(),
			ResourceAttributes: tdr.GetResourceAttributes(),
		})
	}

	resp, err := as.GetDecisions(ctx, &connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: decisionsRequests,
		},
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&authorization.GetDecisionsByTokenResponse{
		DecisionResponses: resp.Msg.GetDecisionResponses(),
	}), err
}

func (as *AuthorizationService) GetDecisions(ctx context.Context, req *connect.Request[authorization.GetDecisionsRequest]) (*connect.Response[authorization.GetDecisionsResponse], error) {
	as.logger.DebugContext(ctx, "getting decisions")

	ctx, span := as.Start(ctx, "GetDecisions")
	defer span.End()

	// Temporary canned echo response with permit decision for all requested decision/entity/ra combos
	rsp := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 0),
	}
	for _, dr := range req.Msg.GetDecisionRequests() {
		resp, err := as.getDecisions(ctx, dr)
		if err != nil {
			return nil, err
		}
		rsp.DecisionResponses = append(rsp.DecisionResponses, resp...)
	}

	return connect.NewResponse(rsp), nil
}

// makeSubMapsByValLookup creates a lookup map of subject mappings by attribute value ID.
func makeSubMapsByValLookup(subjectMappings []*policy.SubjectMapping) map[string][]*policy.SubjectMapping {
	// map keys will be attribute value IDs
	lookup := make(map[string][]*policy.SubjectMapping)
	for _, sm := range subjectMappings {
		val := sm.GetAttributeValue()
		id := val.GetId()
		// if attribute value ID exists
		if id != "" {
			// append the subject mapping to the slice of subject mappings for the attribute value ID
			lookup[id] = append(lookup[id], sm)
		}
	}
	return lookup
}

// updateValsWithSubMaps updates the subject mappings of values using the lookup map.
func updateValsWithSubMaps(values []*policy.Value, subMapsByVal map[string][]*policy.SubjectMapping) []*policy.Value {
	for i, v := range values {
		// if subject mappings exist for the value
		if subjectMappings, ok := subMapsByVal[v.GetId()]; ok {
			// update the subject mappings of the value
			values[i].SubjectMappings = subjectMappings
		}
	}
	return values
}

// updateValsByFqnLookup updates the lookup map with attribute values by FQN.
func updateValsByFqnLookup(attribute *policy.Attribute, scopeMap map[string]bool, fqnAttrVals map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue) map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	rule := attribute.GetRule()
	for _, v := range attribute.GetValues() {
		// if scope exists and current attribute value FQN is not in scope
		if scopeMap != nil && !scopeMap[v.GetFqn()] {
			// skip
			continue
		}
		// trim attribute values (by default only keep single value relevant to FQN)
		// This is key to minimizing the rego query size.
		values := []*policy.Value{v}
		if rule == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
			// restore ALL attribute values if attribute rule is hierarchical
			// This is key to honoring comprehensive hierarchy.
			values = attribute.GetValues()
		}
		// only clone relevant fields for attribute
		a := &policy.Attribute{Rule: rule, Values: values}
		fqnAttrVals[v.GetFqn()] = &attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{Attribute: a, Value: v}
	}
	return fqnAttrVals
}

// makeValsByFqnsLookup creates a lookup map of attribute values by FQN.
func makeValsByFqnsLookup(attrs []*policy.Attribute, subMapsByVal map[string][]*policy.SubjectMapping, scopeMap map[string]bool) map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	fqnAttrVals := make(map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for i := range attrs {
		// add subject mappings to attribute values
		attrs[i].Values = updateValsWithSubMaps(attrs[i].GetValues(), subMapsByVal)
		// update the lookup map with attribute values by FQN
		fqnAttrVals = updateValsByFqnLookup(attrs[i], scopeMap, fqnAttrVals)
	}
	return fqnAttrVals
}

// makeScopeMap creates a map of attribute value FQNs.
func makeScopeMap(scope *authorization.ResourceAttribute) map[string]bool {
	// if scope not defined, return nil pointer
	if scope == nil {
		return nil
	}
	scopeMap := make(map[string]bool)
	// add attribute value FQNs from scope to the map
	for _, fqn := range scope.GetAttributeValueFqns() {
		scopeMap[strings.ToLower(fqn)] = true
	}
	return scopeMap
}

func (as *AuthorizationService) GetEntitlements(ctx context.Context, req *connect.Request[authorization.GetEntitlementsRequest]) (*connect.Response[authorization.GetEntitlementsResponse], error) {
	as.logger.DebugContext(ctx, "getting entitlements")

	ctx, span := as.Start(ctx, "GetEntitlements")
	defer span.End()

	var nextOffset int32
	attrsList := make([]*policy.Attribute, 0)
	subjectMappingsList := make([]*policy.SubjectMapping, 0)

	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	for {
		listed, err := as.sdk.Attributes.ListAttributes(ctx, &attr.ListAttributesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			as.logger.ErrorContext(ctx, "failed to list attributes", slog.String("error", err.Error()))
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list attributes"))
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		attrsList = append(attrsList, listed.GetAttributes()...)

		// offset becomes zero when list is exhausted
		if nextOffset <= 0 {
			break
		}
	}

	// If quantity of subject mappings exceeds maximum list pagination, all are needed to determine entitlements
	nextOffset = 0
	for {
		listed, err := as.sdk.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			as.logger.ErrorContext(ctx, "failed to list subject mappings", slog.String("error", err.Error()))
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list subject mappings"))
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		subjectMappingsList = append(subjectMappingsList, listed.GetSubjectMappings()...)

		// offset becomes zero when list is exhausted
		if nextOffset <= 0 {
			break
		}
	}
	// create a lookup map of attribute value FQNs (based on request scope)
	scopeMap := makeScopeMap(req.Msg.GetScope())
	// create a lookup map of subject mappings by attribute value ID
	subMapsByVal := makeSubMapsByValLookup(subjectMappingsList)
	// create a lookup map of attribute values by FQN (for rego query)
	fqnAttrVals := makeValsByFqnsLookup(attrsList, subMapsByVal, scopeMap)
	avf := &attr.GetAttributeValuesByFqnsResponse{
		FqnAttributeValues: fqnAttrVals,
	}
	subjectMappings := avf.GetFqnAttributeValues()
	as.logger.DebugContext(ctx, "retrieved subject mappings", slog.Int("count", len(subjectMappings)))

	// TODO: this could probably be moved to proto validation https://github.com/opentdf/platform/issues/1057
	if req.Msg.Entities == nil {
		as.logger.ErrorContext(ctx, "requires entities")
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("requires entities"))
	}
	rsp := &authorization.GetEntitlementsResponse{
		Entitlements: make([]*authorization.EntityEntitlements, len(req.Msg.GetEntities())),
	}

	// call ERS on all entities
	ersResp, err := as.sdk.EntityResoution.ResolveEntities(ctx, &entityresolution.ResolveEntitiesRequest{Entities: req.Msg.GetEntities()})
	if err != nil {
		as.logger.ErrorContext(ctx, "error calling ERS to resolve entities", slog.Any("entities", req.Msg.GetEntities()))
		return nil, err
	}

	// call rego on all entities
	in, err := entitlements.OpaInput(subjectMappings, ersResp)
	if err != nil {
		as.logger.ErrorContext(ctx, "failed to build rego input", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to build rego input"))
	}

	results, err := as.eval.Eval(ctx,
		rego.EvalInput(in),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to evaluate entitlements policy"))
	}

	resp := connect.NewResponse(rsp)

	// If we get no results and no error then we assume that the entity is not entitled to anything
	if len(results) == 0 {
		as.logger.DebugContext(ctx, "no entitlement results")
		return resp, nil
	}

	// I am not sure how we would end up with multiple results but lets return an empty entitlement set for now
	if len(results) > 1 {
		as.logger.WarnContext(ctx, "multiple entitlement results", slog.Any("results", results))
		return resp, nil
	}

	// If we get no expressions then we assume that the entity is not entitled to anything
	if len(results[0].Expressions) == 0 {
		as.logger.WarnContext(ctx, "no entitlement expressions", slog.Any("results", results))
		return resp, nil
	}

	resultsEntitlements, entitlementsMapOk := results[0].Expressions[0].Value.(map[string]interface{})
	if !entitlementsMapOk {
		as.logger.ErrorContext(ctx, "entitlements is not a map[string]interface", slog.Any("value", resultsEntitlements))
		return resp, nil
	}
	as.logger.DebugContext(ctx, "rego results", slog.Any("results", results))
	for idx, entity := range req.Msg.GetEntities() {
		// Ensure the entity has an ID
		entityID := entity.GetId()
		if entityID == "" {
			entityID = ent.EntityIDPrefix + strconv.Itoa(idx)
		}
		// Check to maksure if the value is a list. Good validation if someone customizes the rego policy
		entityEntitlements, valueListOk := resultsEntitlements[entityID].([]interface{})
		if !valueListOk {
			as.logger.ErrorContext(ctx, "entitlements is not a map[string]interface", slog.Any("value", resultsEntitlements))
			return resp, nil
		}

		// map for attributes for optional comprehensive
		attributesMap := make(map[string]*policy.Attribute)
		// Build array with length of results
		entitlements := make([]string, len(entityEntitlements))

		// Build entitlements list
		for valueIDX, value := range entityEntitlements {
			entitlement, valueOK := value.(string)
			// If value is not okay skip adding to entitlements
			if !valueOK {
				as.logger.WarnContext(ctx, "issue with adding entitlement",
					slog.String("entity_id", entity.GetId()),
					slog.String("entitlement", entitlement),
				)
				continue
			}
			// if comprehensive and a hierarchy attribute is entitled then add the lower entitlements
			if req.Msg.GetWithComprehensiveHierarchy() {
				entitlements = getComprehensiveHierarchy(attributesMap, avf, entitlement, as, entitlements)
			}
			// Add entitlement to entitlements array
			entitlements[valueIDX] = entitlement
		}
		// Update the entity with its entitlements
		resp.Msg.Entitlements[idx] = &authorization.EntityEntitlements{
			EntityId:           entity.GetId(),
			AttributeValueFqns: entitlements,
		}
	}

	return resp, nil
}

func getAttributesFromRas(ras []*authorization.ResourceAttribute) ([]string, error) {
	var attrFqns []string
	repeats := make(map[string]bool)
	moreThanOneAttr := false
	for _, ra := range ras {
		for _, str := range ra.GetAttributeValueFqns() {
			moreThanOneAttr = true
			if str != "" && !repeats[str] {
				attrFqns = append(attrFqns, str)
				repeats[str] = true
			}
		}
	}

	if moreThanOneAttr && len(attrFqns) == 0 {
		return nil, ErrEmptyStringAttribute
	}
	return attrFqns, nil
}

func (as *AuthorizationService) loadRegoAndBuiltins(cfg *Config) error {
	var (
		entitlementRego []byte
		err             error
	)
	// Build Rego PreparedEvalQuery
	// Load rego from embedded file or custom path
	if cfg.Rego.Path != "" {
		entitlementRego, err = os.ReadFile(cfg.Rego.Path)
		if err != nil {
			return fmt.Errorf("failed to read custom entitlements.rego file: %w", err)
		}
	} else {
		entitlementRego, err = policies.EntitlementsRego.ReadFile("entitlements/entitlements.rego")
		if err != nil {
			return fmt.Errorf("failed to read entitlements.rego file: %w", err)
		}
	}

	// Register builtin
	subjectmappingbuiltin.SubjectMappingBuiltin()

	as.eval, err = rego.New(
		rego.Query(cfg.Rego.Query),
		rego.Module("entitlements.rego", string(entitlementRego)),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("failed to prepare entitlements.rego for eval: %w", err)
	}
	return nil
}

func (as *AuthorizationService) getDecisions(ctx context.Context, dr *authorization.DecisionRequest) ([]*authorization.DecisionResponse, error) {
	allPertinentFQNS := &authorization.ResourceAttribute{AttributeValueFqns: make([]string, 0)}
	response := make([]*authorization.DecisionResponse, len(dr.GetResourceAttributes())*len(dr.GetEntityChains()))

	// TODO: fetching missing FQNs should not lead into a complete failure, rather a list of unknown FQNs would be preferred
	var err error
	var dataAttrDefsAndVals map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue
	allPertinentFQNS.AttributeValueFqns, err = getAttributesFromRas(dr.GetResourceAttributes())
	if err == nil {
		dataAttrDefsAndVals, err = retrieveAttributeDefinitions(ctx, allPertinentFQNS.GetAttributeValueFqns(), as.sdk)
	}
	if err != nil {
		// if attribute an FQN does not exist
		// return deny for all entity chains aginst this RAs
		if errors.Is(err, status.Error(codes.NotFound, db.ErrTextNotFound)) || errors.Is(err, ErrEmptyStringAttribute) {
			for raIdx, ra := range dr.GetResourceAttributes() {
				for ecIdx, ec := range dr.GetEntityChains() {
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
					responseIdx := (raIdx * len(dr.GetEntityChains())) + ecIdx
					response[responseIdx] = decisionResp
				}
			}
			return response, nil
		}
		return nil, db.StatusifyError(ctx, as.logger, err, db.ErrTextGetRetrievalFailed, slog.String("fqns", strings.Join(allPertinentFQNS.GetAttributeValueFqns(), ", ")))
	}

	var allAttrDefs []*policy.Attribute
	for _, v := range dataAttrDefsAndVals {
		allAttrDefs = append(allAttrDefs, v.GetAttribute())
	}
	allAttrDefs, err = populateAttrDefValueFqns(allAttrDefs)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// get the relevant resource attribute fqns
	for _, attrDef := range allAttrDefs {
		if attrDef.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
			for _, value := range attrDef.GetValues() {
				allPertinentFQNS.AttributeValueFqns = append(allPertinentFQNS.AttributeValueFqns, value.GetFqn())
			}
		}
	}

	var ecChainEntitlementsResponse []*connect.Response[authorization.GetEntitlementsResponse]
	for _, ec := range dr.GetEntityChains() {
		entities := ec.GetEntities()
		if len(entities) == 0 {
			ecChainEntitlementsResponse = append(ecChainEntitlementsResponse, nil)
			continue
		}
		req := connect.Request[authorization.GetEntitlementsRequest]{
			Msg: &authorization.GetEntitlementsRequest{
				Entities: entities,
				Scope:    allPertinentFQNS,
			},
		}
		ecEntitlements, err := as.GetEntitlements(ctx, &req)
		if err != nil {
			// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
			return nil, db.StatusifyError(ctx, as.logger, err, db.ErrTextGetRetrievalFailed, slog.String("extra", "getEntitlements request failed"))
		}
		ecChainEntitlementsResponse = append(ecChainEntitlementsResponse, ecEntitlements)
	}

	for raIdx, ra := range dr.GetResourceAttributes() {
		var attrDefs []*policy.Attribute
		var attrVals []*policy.Value
		var fqns []string

		for _, fqn := range ra.GetAttributeValueFqns() {
			fqn = strings.ToLower(fqn)
			fqns = append(fqns, fqn)
			v := dataAttrDefsAndVals[fqn]
			attrDefs = append(attrDefs, v.GetAttribute())
			attrVal := v.GetValue()
			attrVal.Fqn = fqn
			attrVals = append(attrVals, attrVal)
		}

		attrDefs, err = populateAttrDefValueFqns(attrDefs)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		for ecIdx, ec := range dr.GetEntityChains() {
			// check if we already have a decision for this entity chain
			responseIdx := (raIdx * len(dr.GetEntityChains())) + ecIdx
			if response[responseIdx] != nil {
				continue
			}

			//
			// TODO: we should already have the subject mappings here and be able to just use OPA to trim down the known data attr values to the ones matched up with the entities
			//
			entities := ec.GetEntities()
			auditECEntitlements := make([]audit.EntityChainEntitlement, 0)
			auditEntityDecisions := make([]audit.EntityDecision, 0)

			// Entitlements for environment entites in chain
			envEntityAttrValues := make(map[string][]string)
			// Entitlementsfor sbuject entities in chain
			subjectEntityAttrValues := make(map[string][]string)

			// handle empty entity / attr list
			decision := authorization.DecisionResponse_DECISION_DENY
			switch {
			case len(entities) == 0:
				as.logger.WarnContext(ctx, "empty entity list")
			case len(ra.GetAttributeValueFqns()) == 0:
				as.logger.WarnContext(ctx, "empty entity data attribute list")
				decision = authorization.DecisionResponse_DECISION_PERMIT
			default:
				ecEntitlements := ecChainEntitlementsResponse[ecIdx]
				for entIdx, e := range ecEntitlements.Msg.GetEntitlements() {
					entityID := e.GetEntityId()
					if entityID == "" {
						entityID = ent.EntityIDPrefix + strconv.Itoa(entIdx)
					}
					entityCategory := entities[entIdx].GetCategory()
					auditECEntitlements = append(auditECEntitlements, audit.EntityChainEntitlement{
						EntityID:                 entityID,
						EntityCatagory:           entityCategory.String(),
						AttributeValueReferences: e.GetAttributeValueFqns(),
					})

					// If entity type unspecified, include in access decision to err on the side of caution
					if entityCategory == authorization.Entity_CATEGORY_SUBJECT || entityCategory == authorization.Entity_CATEGORY_UNSPECIFIED {
						subjectEntityAttrValues[entityID] = e.GetAttributeValueFqns()
					} else {
						envEntityAttrValues[entityID] = e.GetAttributeValueFqns()
					}
				}
				// call access-pdp
				accessPDP := access.NewPdp(as.logger)
				decisions, err := accessPDP.DetermineAccess(
					ctx,
					attrVals,
					subjectEntityAttrValues,
					attrDefs,
				)
				if err != nil {
					// TODO: should all decisions in a request fail if one entity entitlement lookup fails?
					return nil, db.StatusifyError(ctx, as.logger, errors.New("could not determine access"), "could not determine access", slog.String("error", err.Error()))
				}
				// check the decisions
				decision = authorization.DecisionResponse_DECISION_PERMIT
				for entityID, d := range decisions {
					// Set overall decision as well as individual entity decision
					entityDecision := authorization.DecisionResponse_DECISION_PERMIT
					if !d.Access {
						entityDecision = authorization.DecisionResponse_DECISION_DENY
						decision = authorization.DecisionResponse_DECISION_DENY
					}

					// Add entity decision to audit list
					entityEntitlementFqns := subjectEntityAttrValues[entityID]
					if entityEntitlementFqns == nil {
						entityEntitlementFqns = []string{}
					}
					auditEntityDecisions = append(auditEntityDecisions, audit.EntityDecision{
						EntityID:     entityID,
						Decision:     entityDecision.String(),
						Entitlements: entityEntitlementFqns,
					})
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
			response[responseIdx] = decisionResp
		}
	}
	return response, nil
}

func retrieveAttributeDefinitions(ctx context.Context, attrFqns []string, sdk *otdf.SDK) (map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	if len(attrFqns) == 0 {
		return make(map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue), nil
	}

	resp, err := sdk.Attributes.GetAttributeValuesByFqns(ctx, &attr.GetAttributeValuesByFqnsRequest{
		Fqns: attrFqns,
	})
	if err != nil {
		return nil, err
	}
	// If `allow_traversal` is true for an attribute definition
	// it will return an attribute definition for a missing
	// value. Where before you would receive a 404 error.
	// Since v1 does not expect direct entitlements
	// and expects a value, we fail if there is no
	// value.
	fqnAttrVals := resp.GetFqnAttributeValues()
	for _, fqn := range attrFqns {
		normalized := strings.ToLower(fqn)
		attributeAndValue, ok := fqnAttrVals[normalized]
		if !ok || attributeAndValue == nil || attributeAndValue.GetValue() == nil {
			return nil, status.Error(codes.NotFound, db.ErrTextNotFound)
		}
	}
	return fqnAttrVals, nil
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
		as.logger.Warn("no attribute definition found for entity", slog.String("fqn", entitlement))
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
