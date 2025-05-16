package subjectmappingbuiltin

import (
	"fmt"
	"slices"

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
	results := make(map[string]AttributeValueFQNsToActions)
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
	var entitlementsSet = make(map[string][]*policy.Action)

	for _, entity := range jsonEntities {
		flattenedEntity, err := flattening.Flatten(entity.AsMap())
		if err != nil {
			return nil, fmt.Errorf("failure to flatten entity in subject mapping builtin: %w", err)
		}

		for valueFQN, attributeAndValue := range resolveableAttributes {
			// subject mapping results or-ed together
			for _, subjectMapping := range attributeAndValue.GetValue().GetSubjectMappings() {
				subjectMappingResult := true
				for _, subjectSet := range subjectMapping.GetSubjectConditionSet().GetSubjectSets() {
					subjectSetConditionResult, err := EvaluateSubjectSet(subjectSet, flattenedEntity)
					if err != nil {
						return nil, err
					}
					// update the result for the subject mapping
					subjectMappingResult = subjectMappingResult && subjectSetConditionResult
					// if one subject condition set fails, subject mapping fails
					if !subjectSetConditionResult {
						break
					}
				}

				// each subject mapping that is true should permit the actions on the mapped value
				if subjectMappingResult {
					// add value FQN to the entitlements set
					if _, ok := entitlementsSet[valueFQN]; !ok {
						entitlementsSet[valueFQN] = make([]*policy.Action, 0)
					}
					actions := subjectMapping.GetActions()

					// Cache each action by name to deduplicate
					for _, action := range actions {
						if !slices.ContainsFunc(entitlementsSet[valueFQN], func(a *policy.Action) bool {
							return a.GetName() == action.GetName()
						}) {
							entitlementsSet[valueFQN] = append(entitlementsSet[valueFQN], action)
						}
					}
				}
			}
		}
	}

	return entitlementsSet, nil
}
