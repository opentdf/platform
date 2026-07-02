package subjectmappingbuiltin

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/lib/identifier"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

// DynamicValueMappingsByDefinitionFQN indexes dynamic mappings by their
// parent attribute definition FQN for O(1) lookup during decisioning.
type DynamicValueMappingsByDefinitionFQN map[string][]*policy.DynamicValueMapping

// EvaluateDynamicValueMappingsWithActions resolves the dynamic, definition
// level entitlement mappings for the resources under evaluation. For each decisionable
// attribute value it finds the mappings on the value's parent definition, runs the
// optional static SubjectConditionSet gate, then compares the requested resource value
// segment against the entity representation via the mapping's resolver. On a match the
// mapping's actions are entitled on that concrete value FQN.
//
// The output shape matches EvaluateSubjectMappingsWithActions so the PDP can merge the
// two results uniformly before rule evaluation.
func EvaluateDynamicValueMappingsWithActions(
	mappingsByDefinitionFQN DynamicValueMappingsByDefinitionFQN,
	decisionableAttributes map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entityRepresentation *entityresolutionV2.EntityRepresentation,
	l *slog.Logger,
) (AttributeValueFQNsToActions, error) {
	entitlementsSet := make(AttributeValueFQNsToActions)
	if len(mappingsByDefinitionFQN) == 0 || entityRepresentation == nil {
		return entitlementsSet, nil
	}

	// Flatten each entity in the representation once; a mapping matches if any entity satisfies it.
	flattenedEntities := make([]flattening.Flattened, 0, len(entityRepresentation.GetAdditionalProps()))
	for _, entity := range entityRepresentation.GetAdditionalProps() {
		flattenedEntity, err := flattening.Flatten(entity.AsMap())
		if err != nil {
			return nil, fmt.Errorf("failure to flatten entity in definition value entitlement builtin: %w", err)
		}
		flattenedEntities = append(flattenedEntities, flattenedEntity)
	}

	for valueFQN, attributeAndValue := range decisionableAttributes {
		definitionFQN := attributeAndValue.GetAttribute().GetFqn()
		mappings := mappingsByDefinitionFQN[definitionFQN]
		if len(mappings) == 0 {
			continue
		}

		segment, err := resourceValueSegment(valueFQN, attributeAndValue.GetValue())
		if err != nil {
			return nil, err
		}

		// mappings on the same definition are OR-ed together
		for _, mapping := range mappings {
			// A mapping is satisfied if any entity in the representation matches it. Evaluate
			// existentially and append the mapping's actions at most once per value FQN, so multiple
			// matching entities (e.g. person + client) do not duplicate the entitlement.
			matched := false
			for _, flattenedEntity := range flattenedEntities {
				ok, err := evaluateDynamicValueMapping(mapping, flattenedEntity, segment)
				if err != nil {
					return nil, err
				}
				if ok {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			if _, ok := entitlementsSet[valueFQN]; !ok {
				entitlementsSet[valueFQN] = make([]*policy.Action, 0)
			}
			entitlementsSet[valueFQN] = append(
				entitlementsSet[valueFQN],
				dedupeSubjectMappingActions(mapping.GetActions(), l)...,
			)
		}
	}

	return entitlementsSet, nil
}

// evaluateDynamicValueMapping returns true when the optional static gate
// passes (if present) AND the dynamic resolver matches the resource value segment.
func evaluateDynamicValueMapping(
	mapping *policy.DynamicValueMapping,
	entity flattening.Flattened,
	segment string,
) (bool, error) {
	// optional static pre-gate: all subject sets AND together with normal semantics
	for _, subjectSet := range mapping.GetSubjectConditionSet().GetSubjectSets() {
		ok, err := EvaluateSubjectSet(subjectSet, entity)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}

	return evaluateValueResolver(mapping.GetValueResolver(), entity, segment)
}

// evaluateValueResolver reports whether any entity value resolved by the selector matches the
// requested resource value segment under the resolver's operator. The match is existential over
// the entity values. NOT_IN is unsupported because dynamic resolution is existential.
func evaluateValueResolver(resolver *policy.DynamicValueResolver, entity flattening.Flattened, segment string) (bool, error) {
	operator := resolver.GetOperator()
	var match func(entityValue string) bool
	switch operator {
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
		match = func(entityValue string) bool { return entityValue == segment }
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
		match = func(entityValue string) bool { return strings.Contains(entityValue, segment) }
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN:
		return false, errors.New("NOT_IN is unsupported for dynamic value resolution")
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified dynamic value resolver operator")
	default:
		return false, fmt.Errorf("unsupported dynamic value resolver operator: %s", operator)
	}

	entityValues := flattening.GetFromFlattened(entity, resolver.GetSubjectExternalSelectorValue())
	for _, ev := range entityValues {
		if ev == nil {
			continue
		}
		if match(fmt.Sprintf("%v", ev)) {
			return true, nil
		}
	}
	return false, nil
}

// resourceValueSegment returns the concrete value segment for a resource value FQN,
// preferring the value already parsed onto the policy.Value and falling back to parsing
// the FQN.
func resourceValueSegment(valueFQN string, value *policy.Value) (string, error) {
	if v := value.GetValue(); v != "" {
		return v, nil
	}
	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](valueFQN)
	if err != nil {
		return "", fmt.Errorf("parsing resource value FQN %q: %w", valueFQN, err)
	}
	return parsed.Value, nil
}
