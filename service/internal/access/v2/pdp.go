package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/open-policy-agent/opa/rego"
	"github.com/opentdf/platform/lib/flattening"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrMissingRequiredSDK                          = errors.New("access: missing required SDK")
	ErrMissingRequiredLogger                       = errors.New("access: missing required logger")
	ErrMissingEntityResolutionServiceSDKConnection = errors.New("access: missing required entity resolution SDK connection, cannot be nil")
	ErrInvalidAttributeDefinition                  = errors.New("access: invalid attribute definition")
	ErrInvalidResourceType                         = errors.New("access: invalid resource type")

	defaultFallbackLoggerConfig = logger.Config{
		Level:  "info",
		Type:   "json",
		Output: "stdout",
	}
)

// === Structures ===

// Decision represents the overall access decision for an entity.
type Decision struct {
	Access  bool             `json:"access" example:"false"`
	Results []DataRuleResult `json:"entity_rule_result"`
}

// DataRuleResult represents the result of evaluating one rule for an entity.
type DataRuleResult struct {
	Passed         bool              `json:"passed" example:"false"`
	RuleDefinition *policy.Attribute `json:"rule_definition"`
	ValueFailures  []ValueFailure    `json:"value_failures"`
}

// ValueFailure represents a specific failure when evaluating a data attribute.
type ValueFailure struct {
	DataAttribute *policy.Value `json:"data_attribute"`
	Message       string        `json:"message" example:"Criteria NOT satisfied for entity: {entity_id} - lacked attribute value: {attribute}"`
}

// PDP represents the Policy Decision Point component.
type PDP struct {
	sdk                       *otdfSDK.SDK
	logger                    *logger.Logger
	attributesByDefinitionFQN map[string]*policy.Attribute
	regoEval                  rego.PreparedEvalQuery
}

// NewPDP creates a new Policy Decision Point instance.
// If the definitions are not provided, it will attempt to retrieve all attributes in policy.
func NewPDP(
	ctx context.Context,
	sdk *otdfSDK.SDK,
	l *logger.Logger,
	attributeDefinitions []*policy.Attribute,
	regoEval rego.PreparedEvalQuery,
) (*PDP, error) {
	var err error

	if sdk == nil {
		return nil, ErrMissingRequiredSDK
	}
	if l == nil {
		l, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	pdp := &PDP{
		sdk:    sdk,
		logger: l,
	}

	if attributeDefinitions == nil {
		attributeDefinitions, err = pdp.fetchAllDefinitions(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch attribute definitions: %w", err)
		}
	}

	definitionsMap := make(map[string]*policy.Attribute)
	for _, attr := range attributeDefinitions {
		if attr == nil {
			return nil, fmt.Errorf("attribute definition is nil: %w", ErrInvalidAttributeDefinition)
		}
		if attr.GetFqn() == "" {
			return nil, fmt.Errorf("attribute definition has no FQN: %w", ErrInvalidAttributeDefinition)
		}
		if len(attr.GetValues()) == 0 {
			return nil, fmt.Errorf("attribute definition has no values: %w", ErrInvalidAttributeDefinition)
		}
		definitionsMap[attr.GetFqn()] = attr
	}

	return &PDP{
		sdk:                       sdk,
		attributesByDefinitionFQN: definitionsMap,
		logger:                    l,
		regoEval:                  regoEval,
	}, nil
}

// func (p *PDP) GetDecision(entityChain *authz.EntityChain, action *policy.Action, resources []*authz.Resource) (*Decision, error) {
// }

func (p *PDP) GetEntitlements(
	ctx context.Context,
	entities []*authz.Entity,
	scope *authz.Resource,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	result := make([]*authz.EntityEntitlements, len(entities))

	// call ERS on all entities
	ersResp, err := p.sdk.EntityResoution.ResolveEntities(ctx, &entityresolution.ResolveEntitiesRequest{EntitiesV2: entities})
	if err != nil {
		p.logger.ErrorContext(ctx, "error calling ERS to resolve entities", slog.String("error", err.Error()), slog.Any("entities", entities))
		return nil, err
	}
	entityRepresentations := ersResp.GetEntityRepresentations()

	attributeMappings, err := p.fetchEntitleableAttributes(ctx, entityRepresentations, scope)
	if err != nil {
		p.logger.ErrorContext(ctx, "error fetching entitleable attributes", slog.String("error", err.Error()), slog.Any("scope", scope))
		return nil, err
	}

	entityIDsToFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntitiesWithActions(attributeMappings, entityRepresentations)
	if err != nil {
		p.logger.ErrorContext(ctx, "error evaluating subject mappings for entitlement", slog.String("error", err.Error()), slog.Any("entities", entities))
		return nil, err
	}

	for entityID, fqnsToActions := range entityIDsToFQNsToActions {
		actionsPerAttributeValueFqn := make(map[string]*authz.EntityEntitlements_ActionsList)
		for fqn, actions := range fqnsToActions {
			actionsPerAttributeValueFqn[fqn] = &authz.EntityEntitlements_ActionsList{
				Actions: actions,
			}
		}
		// TODO: withComprehensiveHierarchy needs to be considered here
		result = append(result, &authz.EntityEntitlements{
			EphemeralId:                 entityID,
			ActionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
		})
	}
	return result, nil
}

func (p *PDP) checkAccess(ctx context.Context, entitlements *authz.EntityEntitlements, action *policy.Action, resource *authz.Resource) (bool, error) {
	switch r := resource.GetResource().(type) {
	case *authz.Resource_RegisteredResourceValueFqn:
		p.logger.DebugContext(ctx, "checking access for registered resource value FQN", slog.String("fqn", r.RegisteredResourceValueFqn))
		// TODO: Decompose the registerd resource value into required entitled actions on attribute values
		return false, nil
	case *authz.Resource_AttributeValues_:
		p.logger.DebugContext(ctx, "checking access for resource attribute values", slog.Any("attribute_values", r.AttributeValues.GetFqns()))
		// TODO: check each definition within the rules for access

	default:
		p.logger.ErrorContext(ctx, "unknown resource type", slog.Any("resource", r))
		return false, ErrInvalidResourceType
	}
	return false, nil
}

// fetchAllDefinitions retrieves all attribute definitions within policy
func (p *PDP) fetchAllDefinitions(ctx context.Context) ([]*policy.Attribute, error) {
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	attrsList := make([]*policy.Attribute, 0)

	for {
		listed, err := p.sdk.Attributes.ListAttributes(ctx, &attrs.ListAttributesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to list attributes", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to list attributes: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		attrsList = append(attrsList, listed.GetAttributes()...)

		if nextOffset <= 0 {
			break
		}
	}
	return attrsList, nil
}

func (p *PDP) fetchEntitleableAttributes(ctx context.Context, entityRepresentations []*entityresolution.EntityRepresentation, scope *authz.Resource) (map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	if scope != nil {
		return p.fetchAttributesByScope(ctx, scope)
	}
	subjectProperties := make([]*policy.SubjectProperty, 0)
	for _, entityRep := range entityRepresentations {
		for _, entity := range entityRep.GetAdditionalProps() {
			flattened, err := flattening.Flatten(entity.AsMap())
			if err != nil {
				p.logger.ErrorContext(ctx, "failed to flatten entity representation", slog.String("error", err.Error()))
				return nil, fmt.Errorf("failed to flatten entity representation: %w", err)
			}
			for _, item := range flattened.Items {
				val, ok := item.Value.(string)
				if !ok {
					p.logger.ErrorContext(ctx, "failed to convert value to string", slog.String("value", fmt.Sprintf("%v", item.Value)))
					return nil, fmt.Errorf("failed to convert value to string: %w", err)
				}
				subjectProperties = append(subjectProperties, &policy.SubjectProperty{
					ExternalSelectorValue: item.Key,
					ExternalValue:         val,
				})
			}
		}
	}

	req := &subjectmapping.MatchSubjectMappingsRequest{
		SubjectProperties: subjectProperties,
	}
	subjectMappings, err := p.sdk.SubjectMapping.MatchSubjectMappings(ctx, req)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to match subject mappings", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to match subject mappings: %w", err)
	}
	if subjectMappings == nil {
		p.logger.ErrorContext(ctx, "subject mappings are nil")
		return nil, fmt.Errorf("subject mappings are nil: %w", err)
	}
	result := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, mapping := range subjectMappings.GetSubjectMappings() {
		if mapping == nil {
			p.logger.ErrorContext(ctx, "subject mapping is nil")
			return nil, fmt.Errorf("subject mapping is nil: %w", err)
		}
		if mapping.GetAttributeValue() == nil {
			p.logger.ErrorContext(ctx, "aubject mapping's attribute value is nil")
			return nil, fmt.Errorf("aubject mapping's attribute value is nil: %w", err)
		}
		if mapping.GetActions() == nil {
			p.logger.ErrorContext(ctx, "subject mapping's actions are nil")
			return nil, fmt.Errorf("subject mapping's actions are nil: %w", err)
		}
		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value: mapping.GetAttributeValue(),
		}
		mapped.Value.SubjectMappings = make([]*policy.SubjectMapping, 0)
		mapped.Value.SubjectMappings = append(mapped.Value.SubjectMappings, mapping)
		// TODO: make sure the FQN is present here
		result[mapping.GetAttributeValue().GetFqn()] = mapped
	}
	return result, nil
}

// fetchAttributesByScope retrieves subject mappings based on the provided scope
func (p *PDP) fetchAttributesByScope(ctx context.Context, scope *authz.Resource) (map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	var (
		attrFqns []string
		err      error
	)
	switch r := scope.GetResource().(type) {
	case *authz.Resource_RegisteredResourceValueFqn:
		p.logger.DebugContext(ctx, "fetching scoped subject mappings for registered resource value FQN", slog.String("fqn", r.RegisteredResourceValueFqn))
		// TODO: fully implement this registered resource resolution
	case *authz.Resource_AttributeValues_:
		p.logger.DebugContext(ctx, "fetching scoped subject mappings for resource attribute values", slog.Any("attribute_values", r.AttributeValues.GetFqns()))
		attrFqns = r.AttributeValues.GetFqns()
	default:
		p.logger.ErrorContext(ctx, "unknown resource type", slog.Any("resource", r))
		return nil, ErrInvalidResourceType
	}
	resp, err := p.sdk.Attributes.GetAttributeValuesByFqns(ctx, &attrs.GetAttributeValuesByFqnsRequest{
		Fqns: attrFqns,
	})
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to get attribute values by FQNs", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get attribute values by FQNs: %w", err)
	}
	return resp.GetFqnAttributeValues(), nil
}

// fetchAllSubjectMappings retrieves all subject mappings within policy
func (p *PDP) fetchAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	p.logger.DebugContext(ctx, "fetching all subject mappings")
	// If quantity of subject mappings exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	subjectMappings := make([]*policy.SubjectMapping, 0)

	for {
		listed, err := p.sdk.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to list subject mappings", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to list subject mappings: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		subjectMappings = append(subjectMappings, listed.GetSubjectMappings()...)

		if nextOffset <= 0 {
			break
		}
	}
	return subjectMappings, nil
}
