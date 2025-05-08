package access

import (
	"context"
	"fmt"
	"log/slog"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

// InMemoryPDP represents the Policy Decision Point component with all of policy loaded into memory.
// All decisions and entitlements are evaluated against the in-memory policy.
type InMemoryPDP struct {
	logger                             *logger.Logger
	allEntitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
	// allRegisteredResourcesByValueFQN map[string]*policy.RegisteredResourceValue
}

// NewPDPInMemory creates a new Policy Decision Point instance.
// It is presumed that all Attribute Definitions and Subject Mappings are valid and contain the entirety of entitlement policy.
func NewPDPInMemory(
	ctx context.Context,
	l *logger.Logger,
	allAttributeDefinitions []*policy.Attribute,
	allSubjectMappings []*policy.SubjectMapping,
	// TODO: take in all registered resources and store them in memory by value FQN
	// allRegisteredResources []*policy.RegisteredResource,
) (*InMemoryPDP, error) {
	var err error

	if l == nil {
		l, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	if (allAttributeDefinitions != nil && allSubjectMappings == nil) ||
		(allAttributeDefinitions == nil && allSubjectMappings != nil) ||
		(allAttributeDefinitions == nil && allSubjectMappings == nil) {
		l.ErrorContext(ctx, "invalid arguments", slog.String("error", ErrMissingRequiredPolicy.Error()))
		return nil, ErrMissingRequiredPolicy
	}

	// Build lookup maps to in-memory policy
	allAttributesByDefinitionFQN := make(map[string]*policy.Attribute)
	allEntitleableAttributesByValueFQN := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, attr := range allAttributeDefinitions {
		if err := validateAttribute(attr); err != nil {
			l.Error("invalid attribute definition", slog.String("error", err.Error()))
			return nil, fmt.Errorf("invalid attribute definition: %w", err)
		}
		allAttributesByDefinitionFQN[attr.GetFqn()] = attr
	}
	for _, sm := range allSubjectMappings {
		if err := validateSubjectMapping(sm); err != nil {
			l.Error("invalid subject mapping", slog.String("error", err.Error()))
			return nil, fmt.Errorf("invalid subject mapping: %w", err)
		}
		mappedValue := sm.GetAttributeValue()
		mappedValueFQN := mappedValue.GetFqn()
		if _, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]; ok {
			allEntitleableAttributesByValueFQN[mappedValueFQN].Value.SubjectMappings = append(allEntitleableAttributesByValueFQN[mappedValueFQN].Value.SubjectMappings, sm)
			continue
		}
		// Take subject mapping's attribute value and its definition from memory
		parentDefinition, err := getDefinition(mappedValueFQN, allAttributesByDefinitionFQN)
		if err != nil {
			l.Error("failed to get attribute definition", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to get attribute definition: %w", err)
		}
		mappedValue.SubjectMappings = []*policy.SubjectMapping{sm}
		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     mappedValue,
			Attribute: parentDefinition,
		}
		allEntitleableAttributesByValueFQN[mappedValueFQN] = mapped

	}

	pdp := &InMemoryPDP{
		l,
		allEntitleableAttributesByValueFQN,
	}
	return pdp, nil
}

func (p *InMemoryPDP) GetDecision(ctx context.Context, entityChain *authz.EntityChain, action *policy.Action, resources []*authz.Resource) (*Decision, error) {
	if err := validateGetDecision(entityChain, action, resources); err != nil {
		p.logger.Error("invalid input parameters", slog.String("error", err.Error()))
		return nil, err
	}

	// // Gather scoped entitlements
	// entitlements, err := p.GetBulkEntitlements(ctx, entityChain.GetEntities(), resources, true)
	entitleableAttributes := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	err := p.setEntitleableAttributesByScope(ctx, entityRepresentations, entitleableAttributes)

	return nil, nil
}

func (p *InMemoryPDP) GetEntitlements(
	ctx context.Context,
	entityRepresentations []*entityresolution.EntityRepresentation,
	scope *authz.Resource,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	if err := p.validateGetEntitlements(entityRepresentations, scope, withComprehensiveHierarchy); err != nil {
		p.logger.Error("invalid input parameters", slog.String("error", err.Error()))
		return nil, err
	}

	attributesToCheck := p.allEntitleableAttributesByValueFQN
	if 

	// Resolve them to their entitled FQNs and the actions available on each
	entityIDsToFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntitiesWithActions(p.allEntitleableAttributesByValueFQN, entityRepresentations)
	if err != nil {
		p.logger.ErrorContext(ctx, "error evaluating subject mappings for entitlement", slog.String("error", err.Error()), slog.Any("entities", entityRepresentations))
		return nil, err
	}
	
	result := make([]*authz.EntityEntitlements, len(entityRepresentations))
	for entityID, fqnsToActions := range entityIDsToFQNsToActions {
		actionsPerAttributeValueFqn := make(map[string]*authz.EntityEntitlements_ActionsList)
		for valueFQN, actions := range fqnsToActions {
			entitledActions := &authz.EntityEntitlements_ActionsList{
				Actions: actions,
			}
			actionsPerAttributeValueFqn[valueFQN] = entitledActions

			if withComprehensiveHierarchy {
				err = p.populateLowerValuesIfHierarchy(valueFQN, entitledActions, actionsPerAttributeValueFqn)
				if err != nil {
					p.logger.ErrorContext(ctx, "error populating comprehensive lower hierarchy values", slog.String("error", err.Error()), slog.String("value", valueFQN))
					return nil, err
				}
			}

		}
		result = append(result, &authz.EntityEntitlements{
			EphemeralId:                 entityID,
			ActionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
		})
	}
	return result, nil
}


func (p *InMemoryPDP) validateGetEntitlements(
	entityRepresentations []*entityresolution.EntityRepresentation,
	scope []*authz.Resource,
	withComprehensiveHierarchy bool,
) error {
	if entityRepresentations == nil || len(entityRepresentations) == 0 {
		return fmt.Errorf("empty entity chain: %w", ErrInvalidEntityChain)
	}
	for _, entity := range entityRepresentations {
		if entity == nil {
			return fmt.Errorf("entity is nil: %w", ErrInvalidEntityChain)
		}
	}

	// TODO: is this accurate? going up and down both sides of the hierarchy?
	if scope != nil && len(scope) > 0 && withComprehensiveHierarchy {
		return fmt.Errorf("scopes and comprehensive hierarchy are both provided, and only one is allowed: %w", ErrInvalidParameterMismatch)
	}

	return nil
}

func (p *InMemoryPDP) populateLowerValuesIfHierarchy(valueFQN string, entitledActions *authz.EntityEntitlements_ActionsList, actionsPerAttributeValueFqn map[string]*authz.EntityEntitlements_ActionsList) error {
	attributeAndValue, ok := p.allEntitleableAttributesByValueFQN[valueFQN]
	if !ok {
		return fmt.Errorf("attribute value not found in memory: %s", valueFQN)
	}
	definition := attributeAndValue.GetAttribute()
	if definition.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		lower := false
		for _, value := range definition.GetValues() {
			if lower {
				actionsPerAttributeValueFqn[value.GetFqn()] = entitledActions
			}
			if value.GetFqn() == valueFQN {
				lower = true
			}
		}
	}
	return nil
}

func (p *InMemoryPDP) getInScopePossibleEntitlements(scopes []*authz.Resource) (map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	if scopes == nil || len(scopes) == 0 {
		return nil, fmt.Errorf("invalid resource type: %w", ErrInvalidResourceType)
	}

	entitlements := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, scope := range scopes {
		if scope == nil {
			return nil, fmt.Errorf("invalid resource type: %w", ErrInvalidResourceType)
		}
		switch scope.Resource.(type) {
		case *authz.Resource_AttributeValues:
			values := scope.GetAttributeValues()
			if values == nil {
				return nil, fmt.Errorf("invalid resource type: %w", ErrInvalidResourceType)
			}
			for _, value := range values.GetValues() {
				if value == nil {
					return nil, fmt.Errorf("invalid resource type: %w", ErrInvalidResourceType)
				}
				entitlements[value.GetFqn()] = p.allEntitleableAttributesByValueFQN[value.GetFqn()]
			}
	}
	return entitlements, nil
}