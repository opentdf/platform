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
		slog.Debug("Subject mapping plugin invoked")

		// input handling
		var attributeMappingsMap map[string]string
		var attributeMappings = map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{}
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
			var tempAttributeMappings = attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{}
			attributeMappings[k] = &tempAttributeMappings
			err := protojson.Unmarshal([]byte(v), &tempAttributeMappings)
			if err != nil {
				slog.Debug("error with protojson unmarshal")
				return nil, err
			}
			attributeMappings[k] = &tempAttributeMappings
		}

		// do the mapping evaluation
		res, err := EvaluateSubjectMappings(attributeMappings, entityRepresentations.GetEntityRepresentations())
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

func EvaluateSubjectMappings(attributeMappings map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, entityRepresentations []*entityresolution.EntityRepresentation) ([]string, error) {
	// for now just look at first entity
	// We only provide one input to ERS to resolve
	jsonEntities := entityRepresentations[0].GetAdditionalProps()
	var entitlementsSet = make(map[string]bool)
	entitlements := []string{}
	for _, entity := range jsonEntities {
		flattenedEntity, err := flattening.Flatten(entity.AsMap())
		if err != nil {
			return nil, fmt.Errorf("failure to flatten entity in subject mapping builtin: %w", err)
		}
		for attr, mapping := range attributeMappings {
			// subject mapping results or-ed togethor
			mappingResult := false
			for _, subjectMapping := range mapping.GetValue().GetSubjectMappings() {
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
	for k := range entitlementsSet {
		entitlements = append(entitlements, k)
	}
	return entitlements, nil
}

func EvaluateSubjectSet(subjectSet *policy.SubjectSet, entity flattening.Flattened) (bool, error) {
	// condition groups anded togethor
	subjectSetConditionResult := true
	for _, conditionGroup := range subjectSet.GetConditionGroups() {
		conditionGroupResult, err := EvaluateConditionGroup(conditionGroup, entity)
		if err != nil {
			return false, err
		}
		// update the subject condition set result
		// and together with previous condition group results
		subjectSetConditionResult = subjectSetConditionResult && conditionGroupResult
		// if one condition group fails, subject condition set fails
		if !subjectSetConditionResult {
			break
		}
	}
	return subjectSetConditionResult, nil
}

func EvaluateConditionGroup(conditionGroup *policy.ConditionGroup, entity flattening.Flattened) (bool, error) {
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
	return conditionGroupResult, nil
}

func EvaluateCondition(condition *policy.Condition, entity flattening.Flattened) (bool, error) {
	mappedValues := flattening.GetFromFlattened(entity, condition.GetSubjectExternalSelectorValue())
	// slog.Debug("mapped values", "", mappedValues)
	result := false
	switch condition.GetOperator() {
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
		// slog.Debug("the operator is IN")
		for _, possibleValue := range condition.GetSubjectExternalValues() {
			// slog.Debug("possible value", "", possibleValue)
			for _, mappedValue := range mappedValues {
				// slog.Debug("comparing values: ", "possible=", possibleValue, "mapped=", mappedValue)
				if possibleValue == mappedValue {
					// slog.Debug("comparison true")
					result = true
					break
				}
			}
			if result {
				break
			}
		}
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN:
		var notInResult = true
		for _, possibleValue := range condition.GetSubjectExternalValues() {
			for _, mappedValue := range mappedValues {
				// slog.Debug("comparing values: ", "possible=", possibleValue, "mapped=", mappedValue)
				if possibleValue == mappedValue {
					// slog.Debug("comparison true")
					notInResult = false
					break
				}
			}
			if !notInResult {
				break
			}
		}
		if notInResult {
			result = true
		}
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
		// slog.Debug("the operator is CONTAINS")
		for _, possibleValue := range condition.GetSubjectExternalValues() {
			// slog.Debug("possible value", "", possibleValue)
			for _, mappedValue := range mappedValues {
				mappedValueStr := fmt.Sprintf("%v", mappedValue)
				// slog.Debug("comparing values: ", "possible=", possibleValue, "mapped=", mappedValueStr)
				if strings.Contains(mappedValueStr, possibleValue) {
					result = true
					break
				}
			}
			if result {
				break
			}
		}
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED:
		// unspecified subject mapping operator
		return false, errors.New("unspecified subject mapping operator: " + condition.GetOperator().String())
	default:
		// unsupported subject mapping operator
		return false, errors.New("unsupported subject mapping operator: " + condition.GetOperator().String())
	}
	return result, nil
}
