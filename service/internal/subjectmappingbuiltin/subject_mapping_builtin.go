package subjectmappingbuiltin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
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
	comparison, quantifier := normalizedConditionOperators(condition)
	caseInsensitive := condition.GetCaseInsensitive().GetValue()

	// matches reports whether any mapped (entity) value matches the given comparison value.
	matches := func(comparisonValue string) (bool, error) {
		for _, mappedValue := range mappedValues {
			ok, err := compareEntityValue(comparison, caseInsensitive, fmt.Sprintf("%v", mappedValue), comparisonValue)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}

	switch quantifier {
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY:
		// at least one subject_external_values entry matches at least one mapped value
		for _, comparisonValue := range condition.GetSubjectExternalValues() {
			ok, err := matches(comparisonValue)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_NONE:
		// no subject_external_values entry matches any mapped value
		for _, comparisonValue := range condition.GetSubjectExternalValues() {
			ok, err := matches(comparisonValue)
			if err != nil {
				return false, err
			}
			if ok {
				return false, nil
			}
		}
		return true, nil
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ALL:
		// every subject_external_values entry matches at least one mapped value
		for _, comparisonValue := range condition.GetSubjectExternalValues() {
			ok, err := matches(comparisonValue)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified condition quantifier")
	default:
		return false, errors.New("unsupported condition quantifier: " + quantifier.String())
	}
}

// normalizedConditionOperators returns the comparison and quantifier to evaluate a condition with.
// When the decomposed fields are unset it derives them from the deprecated operator field, so
// conditions authored before the decomposition keep working unchanged.
func normalizedConditionOperators(condition *policy.Condition) (policy.ConditionComparisonOperatorEnum, policy.ConditionQuantifierEnum) {
	comparison := condition.GetComparison()
	quantifier := condition.GetQuantifier()
	if comparison != policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_UNSPECIFIED ||
		quantifier != policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_UNSPECIFIED {
		return comparison, quantifier
	}
	switch condition.GetOperator() { //nolint:staticcheck // deprecated operator retained for backward-compat normalization
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
		return policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS, policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN:
		return policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS, policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_NONE
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
		return policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_CONTAINS, policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED:
		// leaves both UNSPECIFIED so EvaluateCondition returns a clear error
		return comparison, quantifier
	default:
		// leaves both UNSPECIFIED so EvaluateCondition returns a clear error
		return comparison, quantifier
	}
}

// compareEntityValue reports whether an entity value matches a comparison value under the given
// comparison operator. The entity value is the haystack and the comparison value is the needle,
// matching both the static condition (entity value vs authored value) and the dynamic resolver
// (entity value vs requested resource segment). Both operands are whitespace-trimmed, and folded
// to lower case when caseInsensitive.
func compareEntityValue(comparison policy.ConditionComparisonOperatorEnum, caseInsensitive bool, entityValue, comparisonValue string) (bool, error) {
	a := strings.TrimSpace(entityValue)
	b := strings.TrimSpace(comparisonValue)
	if caseInsensitive {
		a = strings.ToLower(a)
		b = strings.ToLower(b)
	}
	switch comparison {
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS:
		return a == b, nil
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_CONTAINS:
		return strings.Contains(a, b), nil
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_STARTS_WITH:
		return strings.HasPrefix(a, b), nil
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_ENDS_WITH:
		return strings.HasSuffix(a, b), nil
	case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified condition comparison operator")
	default:
		return false, fmt.Errorf("unsupported condition comparison operator: %s", comparison)
	}
}
