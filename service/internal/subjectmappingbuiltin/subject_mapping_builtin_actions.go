package subjectmappingbuiltin

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

type AttributeValueFQNsToActions map[string][]*policy.Action

type EntityIDsToEntitlements map[string]AttributeValueFQNsToActions

func EvaluateSubjectMappingMultipleEntitiesWithActions(
	attributeMappings map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entityRepresentations []*entityresolutionV2.EntityRepresentation,
) (EntityIDsToEntitlements, error) {
	results := make(map[string]AttributeValueFQNsToActions, len(entityRepresentations))
	for _, er := range entityRepresentations {
		entitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, er)
		if err != nil {
			return nil, err
		}
		results[er.GetOriginalId()] = entitlements
	}

	return results, nil
}

// Returns a map of attribute value FQNs to each entitled action on the value
func EvaluateSubjectMappingsWithActions(
	resolveableAttributes map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entityRepresentation *entityresolutionV2.EntityRepresentation,
) (AttributeValueFQNsToActions, error) {
	jsonEntities := entityRepresentation.GetAdditionalProps()

	// Accumulator that deduplicates actions across all subject mappings per value FQN
	type actionSet map[string]*policy.Action
	entitlementsAcc := make(map[string]actionSet)

	for _, entity := range jsonEntities {
		flattenedEntity, err := flattening.Flatten(entity.AsMap())
		if err != nil {
			return nil, fmt.Errorf("failure to flatten entity in subject mapping builtin: %w", err)
		}

		// Per-entity caches for subject set and condition group evaluations
		subjectSetCache := make(map[*policy.SubjectSet]bool)
		condGroupCache := make(map[*policy.ConditionGroup]bool)

		for valueFQN, attributeAndValue := range resolveableAttributes {
			for _, subjectMapping := range attributeAndValue.GetValue().GetSubjectMappings() {
				subjectMappingResult := true
				for _, subjectSet := range subjectMapping.GetSubjectConditionSet().GetSubjectSets() {
					subjectSetConditionResult, err := evaluateSubjectSetCached(subjectSet, flattenedEntity, subjectSetCache, condGroupCache)
					if err != nil {
						return nil, err
					}
					subjectMappingResult = subjectMappingResult && subjectSetConditionResult
					if !subjectSetConditionResult {
						break
					}
				}

				// each subject mapping that is true should permit the actions on the mapped value
				if subjectMappingResult {
					if _, ok := entitlementsAcc[valueFQN]; !ok {
						entitlementsAcc[valueFQN] = make(actionSet)
					}
					for _, action := range subjectMapping.GetActions() {
						entitlementsAcc[valueFQN][strings.ToLower(action.GetName())] = action
					}
				}
			}
		}
	}

	// Convert actionSet accumulator to final result shape
	entitlementsSet := make(AttributeValueFQNsToActions, len(entitlementsAcc))
	for fqn, aSet := range entitlementsAcc {
		entitlementsSet[fqn] = make([]*policy.Action, 0, len(aSet))
		for _, a := range aSet {
			entitlementsSet[fqn] = append(entitlementsSet[fqn], a)
		}
	}

	return entitlementsSet, nil
}
