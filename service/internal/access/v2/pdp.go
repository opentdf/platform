package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/lib/identifier"
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
	ErrInvalidSubjectMapping                       = errors.New("access: invalid subject mapping")
	ErrInvalidResourceType                         = errors.New("access: invalid resource type")
	ErrInvalidEntityChain                          = errors.New("access: invalid entity chain")
	ErrInvalidAction                               = errors.New("access: invalid action")

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
	// TODO: document removal of rego as an extension point in v2
	// regoEval                  rego.PreparedEvalQuery
}

// NewPDP creates a new Policy Decision Point instance.
// If the definitions are not provided, it will attempt to retrieve all attributes in policy.
func NewPDP(
	ctx context.Context,
	sdk *otdfSDK.SDK,
	l *logger.Logger,
	attributeDefinitions []*policy.Attribute,
	// regoEval rego.PreparedEvalQuery,
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
		if err := validateAttribute(attr); err != nil {
			l.Error("invalid attribute definition", slog.String("error", err.Error()))
			return nil, fmt.Errorf("invalid attribute definition: %w", err)
		}
		definitionsMap[attr.GetFqn()] = attr
	}

	return &PDP{
		sdk:                       sdk,
		attributesByDefinitionFQN: definitionsMap,
		logger:                    l,
		// regoEval:                  regoEval,
	}, nil
}

func (p *PDP) GetDecision(entityChain *authz.EntityChain, action *policy.Action, resources []*authz.Resource) (*Decision, error) {
	if err := validateGetDecision(entityChain, action, resources); err != nil {
		p.logger.Error("invalid input parameters", slog.String("error", err.Error()))
		return nil, err
	}

	// Retrieve the attributes for the resources being decisioned
	scopedAttributes := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, resourceScope := range resources {
		err := p.setAttributesByScope(context.Background(), resourceScope, scopedAttributes)
		if err != nil {
			p.logger.Error("failed to retrieve attributes by scope", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to set attributes by scope: %w", err)
		}
	}
	// TODO: FINISH THESE
	return nil, nil
}

func (p *PDP) GetEntitlements(
	ctx context.Context,
	entities []*authz.Entity,
	scope *authz.Resource,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	result := make([]*authz.EntityEntitlements, len(entities))

	// Resolve all entities
	ersResp, err := p.sdk.EntityResoution.ResolveEntities(ctx, &entityresolution.ResolveEntitiesRequest{EntitiesV2: entities})
	if err != nil {
		p.logger.ErrorContext(ctx, "error calling ERS to resolve entities", slog.String("error", err.Error()), slog.Any("entities", entities))
		return nil, err
	}

	// Retrieve all relevant attribute values, definitions, and subject mappings to resolve
	entityRepresentations := ersResp.GetEntityRepresentations()
	attributesWithResolvableSubjectMappings := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)

	if scope != nil {
		err = p.setAttributesByScope(ctx, scope, attributesWithResolvableSubjectMappings)
		if err != nil {
			p.logger.ErrorContext(ctx, "error setting attributes by scope", slog.String("error", err.Error()), slog.Any("scope", scope))
			return nil, err
		}
	} else {
		err = p.setEntitleableAttributesFromEntityRepresentations(ctx, entityRepresentations, attributesWithResolvableSubjectMappings)
		if err != nil {
			// TODO: is it safe to log entities/entity representations?
			p.logger.ErrorContext(ctx, "error setting entitleable attributes from entity representations", slog.String("error", err.Error()), slog.Any("entities", entities))
			return nil, err
		}
	}

	// Resolve them to their entitled FQNs and the actions available on each
	entityIDsToFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntitiesWithActions(attributesWithResolvableSubjectMappings, entityRepresentations)
	if err != nil {
		p.logger.ErrorContext(ctx, "error evaluating subject mappings for entitlement", slog.String("error", err.Error()), slog.Any("entities", entities))
		return nil, err
	}

	// Build the response
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

// setEntitleableAttributesFromEntityRepresentations retrieves and populates the entitleable attributes per
// the provided entity reresentations, setting them on the provided entitleableAttributes map, merging any
// subject mappings with existing found under the attribute value FQN key.
func (p *PDP) setEntitleableAttributesFromEntityRepresentations(
	ctx context.Context,
	entityRepresentations []*entityresolution.EntityRepresentation,
	// updated with the results, attrValue FQN to attribute and value with subject mappings
	entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) error {
	// Break the entity down the entities into their properties/selectors and retrieve only those subject mappings
	subjectProperties := make([]*policy.SubjectProperty, 0)
	for _, entityRep := range entityRepresentations {
		for _, entity := range entityRep.GetAdditionalProps() {
			flattened, err := flattening.Flatten(entity.AsMap())
			if err != nil {
				p.logger.ErrorContext(ctx, "failed to flatten entity representation", slog.String("error", err.Error()))
				return fmt.Errorf("failed to flatten entity representation: %w", err)
			}
			for _, item := range flattened.Items {
				// The value in this proto is not considered by the API
				subjectProperties = append(subjectProperties, &policy.SubjectProperty{
					ExternalSelectorValue: item.Key,
				})
			}
		}
	}

	// Retrieve the filtered subject mappings that match an entity property in the SM's SubjectConditionSet selectors
	req := &subjectmapping.MatchSubjectMappingsRequest{
		SubjectProperties: subjectProperties,
	}
	subjectMappings, err := p.sdk.SubjectMapping.MatchSubjectMappings(ctx, req)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to match subject mappings", slog.String("error", err.Error()))
		return fmt.Errorf("failed to match subject mappings: %w", err)
	}
	if subjectMappings == nil {
		p.logger.ErrorContext(ctx, "subject mappings are nil")
		return fmt.Errorf("subject mappings are nil: %w", err)
	}

	for _, sm := range subjectMappings.GetSubjectMappings() {
		if err := validateSubjectMapping(sm); err != nil {
			p.logger.ErrorContext(ctx, "subject mapping is invalid", slog.String("error", err.Error()))
			return fmt.Errorf("subject mapping is invalid: %w", err)
		}

		mappedValue := sm.GetAttributeValue()
		mappedValueFQN := mappedValue.GetFqn()

		// If more than one relevant subject mapping for a value, merge existing with new
		if _, ok := entitleableAttributes[mappedValueFQN]; ok {
			entitleableAttributes[mappedValueFQN].Value.SubjectMappings = append(entitleableAttributes[mappedValueFQN].Value.SubjectMappings, sm)
			continue
		}

		// Take subject mapping's attribute value and its definition from memory
		parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](mappedValueFQN)
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to parse attribute FQN", slog.String("error", err.Error()))
			return fmt.Errorf("failed to parse attribute FQN: %w", err)
		}
		definition := &identifier.FullyQualifiedAttribute{
			Name:      parsed.Name,
			Namespace: parsed.Namespace,
		}
		defFQN := definition.FQN()
		if _, ok := p.attributesByDefinitionFQN[defFQN]; !ok {
			p.logger.ErrorContext(ctx,
				"subject mapping's attribute value contained a definition not found",
				slog.String("definition", defFQN),
				slog.Any("attribute_value", mappedValue),
			)
			return fmt.Errorf("subject mapping's attribute value contained a definition not found: %w", err)
		}

		// Build the value, definition, and subject mapping combination to map under the attribute value FQN
		mappedValue.SubjectMappings = []*policy.SubjectMapping{sm}
		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     mappedValue,
			Attribute: p.attributesByDefinitionFQN[defFQN],
		}

		entitleableAttributes[mappedValueFQN] = mapped
	}
	return nil
}

// setAttributesByScope retrieves attributes definitions, values, and their subject mappings for the provided scope
// and sets them on the provided entitleableAttributes map, appending the subject mappings to any existing found
// under the attribute value FQN key.
func (p *PDP) setAttributesByScope(
	ctx context.Context,
	scope *authz.Resource,
	entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) error {
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
		return ErrInvalidResourceType
	}

	resp, err := p.sdk.Attributes.GetAttributeValuesByFqns(ctx, &attrs.GetAttributeValuesByFqnsRequest{
		Fqns: attrFqns,
	})
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to get attribute values by FQNs", slog.String("error", err.Error()))
		return fmt.Errorf("failed to get attribute values by FQNs: %w", err)
	}

	for valFQN, fullyQualified := range resp.GetFqnAttributeValues() {
		if _, ok := entitleableAttributes[valFQN]; !ok {
			entitleableAttributes[valFQN] = fullyQualified
			continue
		}
		// Already have the attribute value and definition, so merge the subject mappings
		entitleableAttributes[valFQN].Value.SubjectMappings = append(entitleableAttributes[valFQN].Value.SubjectMappings, fullyQualified.Value.SubjectMappings...)
	}
	return nil
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
