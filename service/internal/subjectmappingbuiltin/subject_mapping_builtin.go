package subjectmappingbuiltin

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
)

func EvaluateSubjectSet(subjectSet *policy.SubjectSet, entity flattening.Flattened) (bool, error) {
	// condition groups anded together
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
		notInResult := true
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
