package access

import (
	"context"
	"fmt"
	"log/slog"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	ers "github.com/opentdf/platform/protocol/go/entityresolution"
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

func (p *InMemoryPDP) GetDecision(ctx context.Context, entityRepresentation *ers.EntityRepresentation, action *policy.Action, resources []*authz.Resource) (*Decision, error) {
	if err := validateGetDecision(entityRepresentation, action, resources); err != nil {
		p.logger.Error("invalid input parameters", slog.String("error", err.Error()))
		return nil, err
	}

	decisionableAttributes := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, resource := range resources {
		switch resource.GetResource().(type) {
		case *authz.Resource_RegisteredResourceValueFqn:
			// TODO: handle gathering decisionable attributes of registered resources

		case *authz.Resource_AttributeValues_:
			for _, valueFQN := range resource.GetAttributeValues().GetFqns() {
				attributeAndValue, ok := p.allEntitleableAttributesByValueFQN[valueFQN]
				if !ok {
					p.logger.ErrorContext(ctx, "resource value FQN not found in memory", slog.String("error", ErrInvalidResource.Error()), slog.String("value", valueFQN))
					return nil, ErrInvalidResource
				}
				decisionableAttributes[valueFQN] = attributeAndValue
				err := populateHigherValuesIfHierarchy(valueFQN, attributeAndValue.GetAttribute(), decisionableAttributes)
				if err != nil {
					p.logger.ErrorContext(ctx, "error populating higher hierarchy attribute values", slog.String("error", err.Error()), slog.String("value", valueFQN))
					return nil, err
				}
			}

		default:
			// default should never happen as we validate above
			p.logger.ErrorContext(ctx, "invalid resource type", slog.String("error", ErrInvalidResource.Error()))
			return nil, ErrInvalidResource
		}
	}

	// Resolve them to their entitled FQNs and the actions available on each
	entitledFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingsWithActions(decisionableAttributes, entityRepresentation)
	if err != nil {
		// TODO: is it safe to log entities/entity representations?
		p.logger.ErrorContext(ctx, "error evaluating subject mappings for entitlement", slog.String("error", err.Error()), slog.Any("entity", entityRepresentation))
		return nil, err
	}

	decision := &Decision{
		Access:  true,
		Results: make([]DataRuleResult, 0),
	}
	for _, resource := range resources {
		d, err := getDecisionOnOneResource(ctx, p.logger, decisionableAttributes, entitledFQNsToActions, action, resource)
		if err != nil || d == nil {
			p.logger.ErrorContext(ctx, "error evaluating decision", slog.String("error", err.Error()), slog.Any("resource", resource))
			return nil, err
		}
		if !d.Access {
			decision.Access = false
		}
		decision.Results = append(decision.Results, d.Results...)
	}
	p.logger.DebugContext(
		ctx,
		"decision results",
		slog.String("entity ID", entityRepresentation.GetOriginalId()),
		slog.String("action", action.GetName()),
		slog.Int("resource count", len(resources)),
		slog.Any("decision", decision),
	)

	return decision, nil
}

func (p *InMemoryPDP) GetEntitlements(
	ctx context.Context,
	entityRepresentations []*ers.EntityRepresentation,
	optionalMatchedSubjectMappings []*policy.SubjectMapping,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	err := validateEntityRepresentations(entityRepresentations)
	if err != nil {
		p.logger.Error("invalid input parameters", slog.String("error", err.Error()))
		return nil, err
	}

	var entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue

	// Check entitlement only against the filtered matched subject mappings if provided
	if optionalMatchedSubjectMappings != nil {
		entitleableAttributes, err = getFilteredEntitleableAttributes(optionalMatchedSubjectMappings, p.allEntitleableAttributesByValueFQN)
		if err != nil {
			p.logger.ErrorContext(ctx, "error filtering entitleable attributes from matched subject mappings", slog.String("error", err.Error()))
			return nil, err
		}
	} else {
		// Otherwise, use all entitleable attributes
		entitleableAttributes = p.allEntitleableAttributesByValueFQN
	}

	// Resolve them to their entitled FQNs and the actions available on each
	entityIDsToFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntitiesWithActions(entitleableAttributes, entityRepresentations)
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

			// If comprehensive, populate the lower hierarchy values
			if withComprehensiveHierarchy {
				err = populateLowerValuesIfHierarchy(valueFQN, entitleableAttributes, entitledActions, actionsPerAttributeValueFqn)
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
