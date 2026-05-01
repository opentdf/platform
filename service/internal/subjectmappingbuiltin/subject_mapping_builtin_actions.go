package subjectmappingbuiltin

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
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
	l *slog.Logger,
) (EntityIDsToEntitlements, error) {
	results := make(map[string]AttributeValueFQNsToActions, len(entityRepresentations))
	for _, er := range entityRepresentations {
		entitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, er, l)
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
	l *slog.Logger,
) (AttributeValueFQNsToActions, error) {
	jsonEntities := entityRepresentation.GetAdditionalProps()
	entitlementsSet := make(map[string][]*policy.Action)

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
					if _, ok := entitlementsSet[valueFQN]; !ok {
						entitlementsSet[valueFQN] = make([]*policy.Action, 0)
					}
					entitlementsSet[valueFQN] = append(
						entitlementsSet[valueFQN],
						dedupeSubjectMappingActions(subjectMapping.GetActions(), l)...,
					)
				}
			}
		}
	}

	return entitlementsSet, nil
}

// dedupeSubjectMappingActions caches actions by lowercased name and returns
// the deduplicated set. In normal operation, same-name conflicting actions
// should be prevented earlier by policy service create/update validation,
// which enforces namespace consistency between subject mappings and referenced
// actions. This extra conflict check is defensive for unexpected or mixed
// legacy states in-memory; if encountered, keep deterministic behavior and log.
func dedupeSubjectMappingActions(actions []*policy.Action, l *slog.Logger) []*policy.Action {
	m := make(map[string]*policy.Action, len(actions))
	for _, action := range actions {
		key := strings.ToLower(action.GetName())
		existing, ok := m[key]
		if !ok {
			m[key] = action
			continue
		}
		if actionsConflict(existing, action) && l != nil {
			l.Warn(
				"subject mapping action name collision with conflicting identity; using deterministic preference",
				slog.String("action_name", key),
				slog.Any("existing_action", existing),
				slog.Any("candidate_action", action),
			)
		}
		m[key] = preferAction(existing, action)
	}
	return slices.Collect(maps.Values(m))
}

func actionsConflict(existing *policy.Action, candidate *policy.Action) bool {
	if existing == nil || candidate == nil {
		return false
	}

	if existing.GetId() != candidate.GetId() {
		return true
	}

	existingNS := existing.GetNamespace()
	candidateNS := candidate.GetNamespace()
	if existingNS == nil && candidateNS == nil {
		return false
	}
	if (existingNS == nil) != (candidateNS == nil) {
		return true
	}

	if existingNS.GetId() != candidateNS.GetId() {
		return true
	}

	return !strings.EqualFold(existingNS.GetFqn(), candidateNS.GetFqn())
}

func preferAction(existing *policy.Action, candidate *policy.Action) *policy.Action {
	if existing == nil {
		return candidate
	}
	if candidate == nil {
		return existing
	}

	if existing.GetId() == "" && candidate.GetId() != "" {
		return candidate
	}
	if existing.GetId() != "" && candidate.GetId() == "" {
		return existing
	}

	existingNS := existing.GetNamespace()
	candidateNS := candidate.GetNamespace()
	existingHasNS := existingNS != nil && (existingNS.GetId() != "" || existingNS.GetFqn() != "")
	candidateHasNS := candidateNS != nil && (candidateNS.GetId() != "" || candidateNS.GetFqn() != "")

	if !existingHasNS && candidateHasNS {
		return candidate
	}
	if existingHasNS && !candidateHasNS {
		return existing
	}

	return existing
}
