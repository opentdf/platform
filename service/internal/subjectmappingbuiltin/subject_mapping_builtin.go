package subjectmappingbuiltin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/protobuf/encoding/protojson"
)

func SubjectMappingBuiltin() {
	rego.RegisterBuiltin2(&rego.Function{
		Name:             "subjectmapping.resolve",
		Decl:             types.NewFunction(types.Args(types.A, types.A), types.A),
		Memoize:          true,
		Nondeterministic: true,
	}, func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		slog.Debug("subject mapping plugin invoked")

		// input handling
		var attributeMappingsMap map[string]string
		attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{}
		var entityRepresentationsString string
		var entityRepresentations entityresolution.ResolveEntitiesResponse

		if err := ast.As(a.Value, &attributeMappingsMap); err != nil {
			return nil, err
		} else if err := ast.As(b.Value, &entityRepresentationsString); err != nil {
			return nil, err
		}

		entityRepresentationsBytes := []byte(entityRepresentationsString)
		err := protojson.Unmarshal(entityRepresentationsBytes, &entityRepresentations)
		if err != nil {
			return nil, err
		}

		// need to do extra conversion for pbjson within map
		for k, v := range attributeMappingsMap {
			tempAttributeMappings := attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{}
			attributeMappings[k] = &tempAttributeMappings
			err := protojson.Unmarshal([]byte(v), &tempAttributeMappings)
			if err != nil {
				slog.Debug("error with protojson unmarshal")
				return nil, err
			}
			attributeMappings[k] = &tempAttributeMappings
		}

		// do the mapping evaluation
		res, err := EvaluateSubjectMappingMultipleEntities(attributeMappings, entityRepresentations.GetEntityRepresentations())
		if err != nil {
			return nil, err
		}

		// output handling
		respBytes, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		reader := bytes.NewReader(respBytes)
		v, err := ast.ValueFromReader(reader)
		if err != nil {
			return nil, err
		}

		return ast.NewTerm(v), nil
	},
	)
}

func EvaluateSubjectMappingMultipleEntities(attributeMappings map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, entityRepresentations []*entityresolution.EntityRepresentation) (map[string][]string, error) {
	results := make(map[string][]string)
	for _, er := range entityRepresentations {
		entitlements, err := EvaluateSubjectMappings(attributeMappings, er)
		if err != nil {
			return nil, err
		}
		results[er.GetOriginalId()] = entitlements
	}

	return results, nil
}

func EvaluateSubjectMappings(attributeMappings map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, entityRepresentation *entityresolution.EntityRepresentation) ([]string, error) {
	// for now just look at first entity
	// We only provide one input to ERS to resolve
	jsonEntities := entityRepresentation.GetAdditionalProps()
	entitlementsSet := make(map[string]bool)

	for _, entity := range jsonEntities {
		flattenedEntity, err := flattening.Flatten(entity.AsMap())
		if err != nil {
			return nil, fmt.Errorf("failure to flatten entity in subject mapping builtin: %w", err)
		}

		// Per-entity caches to avoid re-evaluating the same subject sets/groups across mappings
		subjectSetCache := make(map[*policy.SubjectSet]bool)
		condGroupCache := make(map[*policy.ConditionGroup]bool)

		for attr, mapping := range attributeMappings {
			// subject mapping results or-ed together
			mappingResult := false
			for _, subjectMapping := range mapping.GetValue().GetSubjectMappings() {
				subjectMappingResult := true
				for _, subjectSet := range subjectMapping.GetSubjectConditionSet().GetSubjectSets() {
					subjectSetConditionResult, err := evaluateSubjectSetCached(subjectSet, flattenedEntity, subjectSetCache, condGroupCache)
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
				// update the result for the attribute mapping
				mappingResult = mappingResult || subjectMappingResult
				// if we find one subject mapping that is true then attribute should be mapped
				if mappingResult {
					break
				}
			}
			if mappingResult {
				entitlementsSet[attr] = true
			}
		}
	}

	entitlements := make([]string, 0, len(entitlementsSet))
	for k := range entitlementsSet {
		entitlements = append(entitlements, k)
	}
	return entitlements, nil
}

// evaluateSubjectSetCached evaluates a subject set with caching keyed by pointer identity.
func evaluateSubjectSetCached(subjectSet *policy.SubjectSet, entity flattening.Flattened, subjectSetCache map[*policy.SubjectSet]bool, condGroupCache map[*policy.ConditionGroup]bool) (bool, error) {
	if res, ok := subjectSetCache[subjectSet]; ok {
		return res, nil
	}

	// condition groups anded together
	subjectSetConditionResult := true
	for _, conditionGroup := range subjectSet.GetConditionGroups() {
		conditionGroupResult, err := evaluateConditionGroupCached(conditionGroup, entity, condGroupCache)
		if err != nil {
			return false, err
		}
		// and together with previous condition group results
		subjectSetConditionResult = subjectSetConditionResult && conditionGroupResult
		// if one condition group fails, subject condition set fails
		if !subjectSetConditionResult {
			break
		}
	}

	subjectSetCache[subjectSet] = subjectSetConditionResult
	return subjectSetConditionResult, nil
}

func EvaluateSubjectSet(subjectSet *policy.SubjectSet, entity flattening.Flattened) (bool, error) {
	// Create ephemeral caches for a single-call path
	return evaluateSubjectSetCached(subjectSet, entity, make(map[*policy.SubjectSet]bool), make(map[*policy.ConditionGroup]bool))
}

func evaluateConditionGroupCached(conditionGroup *policy.ConditionGroup, entity flattening.Flattened, condGroupCache map[*policy.ConditionGroup]bool) (bool, error) {
	if res, ok := condGroupCache[conditionGroup]; ok {
		return res, nil
	}

	// get boolean operator for condition group
	var conditionGroupResult bool
	switch conditionGroup.GetBooleanOperator() {
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND:
		conditionGroupResult = true
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR:
		conditionGroupResult = false
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified condition group boolean operator: " + conditionGroup.GetBooleanOperator().String())
	default:
		// unsupported boolean operator
		return false, errors.New("unsupported condition group boolean operator: " + conditionGroup.GetBooleanOperator().String())
	}

ConditionEval:
	for _, condition := range conditionGroup.GetConditions() {
		conditionResult, err := EvaluateCondition(condition, entity)
		if err != nil {
			return false, err
		}
		switch conditionGroup.GetBooleanOperator() {
		case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND:
			// update result for condition group
			conditionGroupResult = conditionGroupResult && conditionResult
			// if we find a false condition, whole group is false bc AND
			if !conditionGroupResult {
				break ConditionEval
			}
		case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR:
			// update result for condition group
			conditionGroupResult = conditionGroupResult || conditionResult
			// if we find a true condition, whole group is true bc OR
			if conditionGroupResult {
				break ConditionEval
			}
		case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED:
			return false, errors.New("unspecified condition group boolean operator: " + conditionGroup.GetBooleanOperator().String())
		default:
			// unsupported boolean operator
			return false, errors.New("unsupported condition group boolean operator: " + conditionGroup.GetBooleanOperator().String())
		}
	}

	condGroupCache[conditionGroup] = conditionGroupResult
	return conditionGroupResult, nil
}

func EvaluateConditionGroup(conditionGroup *policy.ConditionGroup, entity flattening.Flattened) (bool, error) {
	return evaluateConditionGroupCached(conditionGroup, entity, make(map[*policy.ConditionGroup]bool))
}

func EvaluateCondition(condition *policy.Condition, entity flattening.Flattened) (bool, error) {
	mappedValues := flattening.GetFromFlattened(entity, condition.GetSubjectExternalSelectorValue())

	switch condition.GetOperator() {
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
		// Build set of possible values for O(1) lookup
		possible := condition.GetSubjectExternalValues()
		if len(possible) == 0 || len(mappedValues) == 0 {
			return false, nil
		}
		possibleSet := make(map[string]struct{}, len(possible))
		for _, pv := range possible {
			possibleSet[pv] = struct{}{}
		}
		for _, mv := range mappedValues {
			if s, ok := mv.(string); ok {
				if _, found := possibleSet[s]; found {
					return true, nil
				}
			}
		}
		return false, nil

	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN:
		possible := condition.GetSubjectExternalValues()
		if len(possible) == 0 {
			return true, nil
		}
		possibleSet := make(map[string]struct{}, len(possible))
		for _, pv := range possible {
			possibleSet[pv] = struct{}{}
		}
		for _, mv := range mappedValues {
			if s, ok := mv.(string); ok {
				if _, found := possibleSet[s]; found {
					return false, nil
				}
			}
		}
		return true, nil

	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
		// Fast-path for string mapped values; fallback to fmt.Sprint only when necessary
		for _, possibleValue := range condition.GetSubjectExternalValues() {
			for _, mappedValue := range mappedValues {
				var mappedValueStr string
				switch v := mappedValue.(type) {
				case string:
					mappedValueStr = v
				case []byte:
					mappedValueStr = string(v)
				default:
					mappedValueStr = fmt.Sprint(mappedValue)
				}
				if strings.Contains(mappedValueStr, possibleValue) {
					return true, nil
				}
			}
		}
		return false, nil

	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified subject mapping operator: " + condition.GetOperator().String())
	default:
		return false, errors.New("unsupported subject mapping operator: " + condition.GetOperator().String())
	}
}
