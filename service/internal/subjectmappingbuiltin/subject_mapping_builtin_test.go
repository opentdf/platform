package subjectmappingbuiltin_test

import (
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SubjectSet Benchmark
func BenchmarkEvaluateSubjectSet(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := subjectmappingbuiltin.EvaluateSubjectSet(&subjectSet1, flattenedEntity1)
		if err != nil {
			b.Error(err)
		}
	}
}

// evaluate condition IN
var inCondition1 policy.Condition = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
	SubjectExternalValues:        []string{"option1", "option2"},
}

var entity1 = map[string]interface{}{
	"attributes": map[string]interface{}{
		"testing": []any{"option1", "option3"},
	},
}

var (
	flattenedEntity1, _ = flattening.Flatten(entity1)
	entity2             = map[string]any{
		"attributes": map[string]interface{}{
			"testing": []any{"option4", "option3"},
		},
	}
)

var (
	flattenedEntity2, _ = flattening.Flatten(entity2)
	entity3             = map[string]any{
		"attributes": map[string]interface{}{
			"testing": []any{"option1", "option4"},
		},
	}
)
var flattenedEntity3, _ = flattening.Flatten(entity3)

func Test_EvaluateConditionINTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&inCondition1, flattenedEntity1)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionINFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&inCondition1, flattenedEntity2)
	require.NoError(t, err)
	assert.False(t, res)
}

// evaluate condition NOTIN
var notInCondition2 policy.Condition = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
	SubjectExternalValues:        []string{"option1", "option2"},
}

func Test_EvaluateConditionNOTINTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&notInCondition2, flattenedEntity2)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionNOTINFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&notInCondition2, flattenedEntity1)
	require.NoError(t, err)
	assert.False(t, res)
}

// evaluate condition CONTAINS both in list
var containsCondition1 = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
	SubjectExternalValues:        []string{"option"},
}

// evaluate condition CONTAINS one in list which is 4
var containsCondition4 = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
	SubjectExternalValues:        []string{"4"},
}

// evaluate condition CONTAINS
var containsCondition2 = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
	SubjectExternalValues:        []string{"not-an-option"},
}

func Test_EvaluateConditionCONTAINSAllTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&containsCondition1, flattenedEntity2)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionCONTAINSAnyTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&containsCondition4, flattenedEntity3)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionCONTAINSFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateCondition(&containsCondition2, flattenedEntity1)
	require.NoError(t, err)
	assert.False(t, res)
}

// evaluate condition group AND
var notInCondition3 policy.Condition = policy.Condition{
	SubjectExternalSelectorValue: ".attributes.testing[]",
	Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
	SubjectExternalValues:        []string{"option4", "option5"},
}

var andConditionGroup1 policy.ConditionGroup = policy.ConditionGroup{
	BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
	Conditions: []*policy.Condition{
		&inCondition1, &notInCondition3,
	},
}

func Test_EvaluateConditionGroupANDTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&andConditionGroup1, flattenedEntity1)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionGroupANDFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&andConditionGroup1, flattenedEntity2)
	require.NoError(t, err)
	assert.False(t, res)
}

// evaluate condition group OR
var orConditionGroup1 policy.ConditionGroup = policy.ConditionGroup{
	BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
	Conditions: []*policy.Condition{
		&notInCondition3, &inCondition1,
	},
}

func Test_EvaluateConditionGroupORTrueBoth(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&orConditionGroup1, flattenedEntity1)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionGroupORTrueOne(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&orConditionGroup1, flattenedEntity3)
	require.NoError(t, err)
	assert.True(t, res)
}

func Test_EvaluateConditionGroupORFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateConditionGroup(&orConditionGroup1, flattenedEntity2)
	require.NoError(t, err)
	assert.False(t, res)
}

// evaluate subject sets
var subjectSet1 policy.SubjectSet = policy.SubjectSet{
	ConditionGroups: []*policy.ConditionGroup{
		&andConditionGroup1, &orConditionGroup1,
	},
}

func Test_EvaluateSubjectSetTrue(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateSubjectSet(&subjectSet1, flattenedEntity1)
	require.NoError(t, err)
	assert.True(t, res)
}

var andConditionGroup2 policy.ConditionGroup = policy.ConditionGroup{
	BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
	Conditions: []*policy.Condition{
		&inCondition1, &notInCondition2,
	},
}

var subjectSet2 policy.SubjectSet = policy.SubjectSet{
	ConditionGroups: []*policy.ConditionGroup{
		&andConditionGroup1, &andConditionGroup2,
	},
}

func Test_EvaluateSubjectSetFalse(t *testing.T) {
	res, err := subjectmappingbuiltin.EvaluateSubjectSet(&subjectSet2, flattenedEntity1)
	require.NoError(t, err)
	assert.False(t, res)
}
