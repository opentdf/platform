package subjectmappingbuiltin_test

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Subject Mapping evaluation tests

// evaluate condition IN
var inCondition1 policy.Condition = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum(policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
	SubjectExternalValues:        []string{"option1", "option2"},
}
var entity1 map[string]any = map[string]interface{}{
	"attributes": map[string]interface{}{
		"testing": []any{"option1", "option3"},
	},
}
var entity2 map[string]any = map[string]any{
	"attributes": map[string]interface{}{
		"testing": []any{"option4", "option3"},
	},
}
var entity3 map[string]any = map[string]any{
	"attributes": map[string]interface{}{
		"testing": []any{"option1", "option4"},
	},
}

func Test_EvaluateConditionINTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&inCondition1, entity1)
	require.NoError(t, err)
	assert.Equal(t, true, res)
}
func Test_EvaluateConditionINFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&inCondition1, entity2)
	require.NoError(t, err)
	assert.Equal(t, false, res)
}

// evaluate condition NOTIN
var notInCondition2 policy.Condition = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum(policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN),
	SubjectExternalValues:        []string{"option1", "option2"},
}

func Test_EvaluateConditionNOTINTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&notInCondition2, entity2)
	require.NoError(t, err)
	assert.Equal(t, true, res)
}
func Test_EvaluateConditionNOTINFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&notInCondition2, entity1)
	require.NoError(t, err)
	assert.Equal(t, false, res)
}

// evaluate condition group AND
var notInCondition3 policy.Condition = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum(policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN),
	SubjectExternalValues:        []string{"option4", "option5"},
}

var andConditionGroup1 policy.ConditionGroup = policy.ConditionGroup{
	BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
	Conditions: []*policy.Condition{
		&inCondition1, &notInCondition3,
	},
}

func Test_EvaluateConditionGroupANDTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&andConditionGroup1, entity1)
	require.NoError(t, err)
	assert.Equal(t, true, res)
}
func Test_EvaluateConditionGroupANDFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&andConditionGroup1, entity2)
	require.NoError(t, err)
	assert.Equal(t, false, res)
}

// evaluate condition group OR
var orConditionGroup1 policy.ConditionGroup = policy.ConditionGroup{
	BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
	Conditions: []*policy.Condition{
		&notInCondition3, &inCondition1,
	},
}

func Test_EvaluateConditionGroupORTrueBoth(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&orConditionGroup1, entity1)
	require.NoError(t, err)
	assert.Equal(t, true, res)
}
func Test_EvaluateConditionGroupORTrueOne(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&orConditionGroup1, entity3)
	require.NoError(t, err)
	assert.Equal(t, true, res)
}

func Test_EvaluateConditionGroupORFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&orConditionGroup1, entity2)
	require.NoError(t, err)
	assert.Equal(t, false, res)
}
