package subjectmappingbuiltin

import (
	"bytes"
	"encoding/json"
	"log/slog"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

func SubjectMappingBuiltin() {
	rego.RegisterBuiltin2(&rego.Function{
		Name:             "subjectmapping.resolve",
		Decl:             types.NewFunction(types.Args(types.A, types.A), types.A),
		Memoize:          true,
		Nondeterministic: true,
	}, func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		slog.Debug("Subject mapping plugin invoked")

		//input handling
		var attribute_mappings map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue
		var entity_representations []map[string]any

		if err := ast.As(a.Value, &attribute_mappings); err != nil {
			return nil, err
		} else if err := ast.As(b.Value, &entity_representations); err != nil {
			return nil, err
		}

		// do the work
		res, err := EvaluateSubjectMappings(attribute_mappings, entity_representations)
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

func EvaluateSubjectMappings(attribute_mappings map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, entity_representations []map[string]any) ([]string, error) {
	// for now just look at first entity
	entity := entity_representations[0]
	var entitlements []string
	for attr, mapping := range attribute_mappings {
		// subject mapping results or-ed togethor
		mapping_result := false
		for _, subject_mapping := range mapping.Value.SubjectMappings {
			subject_mapping_result := true
			for _, subject_set := range subject_mapping.SubjectConditionSet.SubjectSets {
				subject_set_condition_result, err := EvaluateSubjectSet(subject_set, entity)
				if err != nil {
					return nil, err
				}
				// update the result for the subject mapping
				subject_mapping_result = subject_mapping_result && subject_set_condition_result
				// if one subject condition set fails, subject mapping fails
				if !subject_set_condition_result {
					break
				}
			}
			// update the result for the attribute mapping
			mapping_result = mapping_result || subject_mapping_result
			// if we find one subject mapping that is true then attribute should be mapped
			if mapping_result {
				break
			}
		}
		if mapping_result {
			entitlements = append(entitlements, attr)
		}
	}
	return entitlements, nil
}

func EvaluateSubjectSet(subject_set *policy.SubjectSet, entity map[string]any) (bool, error) {
	// condition groups anded togethor
	subject_set_condition_result := true
	for _, condition_group := range subject_set.ConditionGroups {
		condition_group_result, err := EvaluateConditionGroup(condition_group, entity)
		if err != nil {
			return false, err
		}
		// update the subject condition set result
		// and togethor with previous condition group results
		subject_set_condition_result = subject_set_condition_result && condition_group_result
		// if one condition group fails, subject condition set fails
		if !subject_set_condition_result {
			break
		}
	}
	return subject_set_condition_result, nil
}

func EvaluateConditionGroup(condition_group *policy.ConditionGroup, entity map[string]any) (bool, error) {
	// get boolean operator for condition group
	var condition_group_result bool
	if condition_group.BooleanOperator == policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND {
		condition_group_result = true
	} else if condition_group.BooleanOperator == policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR {
		condition_group_result = false
	} else {
		// idk how to handle
	}
	for _, condition := range condition_group.Conditions {
		condition_result, err := EvaluateCondition(condition, entity)
		if err != nil {
			return false, err
		}
		if condition_group.BooleanOperator == policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND {
			// update result for condition group
			condition_group_result = condition_group_result && condition_result
			// if we find a false condition, whole group is false bc AND
			if !condition_group_result {
				break
			}
		} else if condition_group.BooleanOperator == policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR {
			// update result for condition group
			condition_group_result = condition_group_result || condition_result
			// if we find a true condition, whole group is true bc OR
			if condition_group_result {
				break
			}
		} else {
			// idk how to handle
		}
	}
	return condition_group_result, nil
}

func EvaluateCondition(condition *policy.Condition, entity map[string]any) (bool, error) {
	mappedValues, err := ExecuteQuery(entity, condition.SubjectExternalSelectorValue)
	if err != nil {
		return false, err
	}
	// slog.Info("mapped values", "", mappedValues)
	result := false
	if condition.Operator == policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN {
		// slog.Info("the operator is IN")
		for _, possibleValue := range condition.SubjectExternalValues {
			// slog.Info("possible value", "", possibleValue)
			for _, mappedValue := range mappedValues {
				// slog.Info("comparing values: ", "possible=", possibleValue, "mapped=", mappedValue)
				if possibleValue == mappedValue {
					// slog.Info("comparison true")
					result = true
					break
				}
			}
			if result {
				break
			}
		}
	} else if condition.Operator == policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN {
		var notInResult = true
		for _, possibleValue := range condition.SubjectExternalValues {
			for _, mappedValue := range mappedValues {
				// slog.Info("comparing values: ", "possible=", possibleValue, "mapped=", mappedValue)
				if possibleValue == mappedValue {
					// slog.Info("comparison true")
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

	} else {
		// not sure how to handle
	}
	return result, nil
}
