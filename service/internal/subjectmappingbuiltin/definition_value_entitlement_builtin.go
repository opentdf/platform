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

// DefinitionValueEntitlementMappingsByDefinitionFQN indexes dynamic mappings by their
// parent attribute definition FQN for O(1) lookup during decisioning.
type DefinitionValueEntitlementMappingsByDefinitionFQN map[string][]*policy.DefinitionValueEntitlementMapping

// EvaluateDefinitionValueEntitlementMappingsWithActions resolves the dynamic, definition
// level entitlement mappings for the resources under evaluation. For each decisionable
// attribute value it finds the mappings on the value's parent definition, runs the
// optional static SubjectConditionSet gate, then compares the requested resource value
// segment against the entity representation via the mapping's resolver. On a match the
// mapping's actions are entitled on that concrete value FQN.
//
// The output shape matches EvaluateSubjectMappingsWithActions so the PDP can merge the
// two results uniformly before rule evaluation.
func EvaluateDefinitionValueEntitlementMappingsWithActions(
	mappingsByDefinitionFQN DefinitionValueEntitlementMappingsByDefinitionFQN,
	decisionableAttributes map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entityRepresentation *entityresolutionV2.EntityRepresentation,
	l *slog.Logger,
) (AttributeValueFQNsToActions, error) {
	entitlementsSet := make(AttributeValueFQNsToActions)
	if len(mappingsByDefinitionFQN) == 0 {
		return entitlementsSet, nil
	}

	for _, entity := range entityRepresentation.GetAdditionalProps() {
		flattenedEntity, err := flattening.Flatten(entity.AsMap())
		if err != nil {
			return nil, fmt.Errorf("failure to flatten entity in definition value entitlement builtin: %w", err)
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
				matched, err := evaluateDefinitionValueEntitlementMapping(mapping, flattenedEntity, segment)
				if err != nil {
					return nil, err
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
	}

	return entitlementsSet, nil
}

// evaluateDefinitionValueEntitlementMapping returns true when the optional static gate
// passes (if present) AND the dynamic resolver matches the resource value segment.
func evaluateDefinitionValueEntitlementMapping(
	mapping *policy.DefinitionValueEntitlementMapping,
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

// evaluateValueResolver compares the resource value segment against the entity values
// resolved by the selector, applying the dynamic operator. Both sides are canonicalized
// (lowercased + trimmed) so external systems that disagree with policy on case still match.
func evaluateValueResolver(resolver *policy.DefinitionValueResolver, entity flattening.Flattened, segment string) (bool, error) {
	selector := resolver.GetSubjectExternalSelectorValue()
	entityValues := flattening.GetFromFlattened(entity, selector)
	target := canonicalizeValueSegment(segment)

	switch resolver.GetOperator() {
	case policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN:
		for _, ev := range entityValues {
			if canonicalizeValueSegment(fmt.Sprintf("%v", ev)) == target {
				return true, nil
			}
		}
		return false, nil
	case policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN_CONTAINS:
		for _, ev := range entityValues {
			if strings.Contains(canonicalizeValueSegment(fmt.Sprintf("%v", ev)), target) {
				return true, nil
			}
		}
		return false, nil
	case policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified dynamic value operator")
	default:
		return false, fmt.Errorf("unsupported dynamic value operator: %s", resolver.GetOperator())
	}
}

func canonicalizeValueSegment(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
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
