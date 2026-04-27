package policy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	policyproto "github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestOperatorConstants(t *testing.T) {
	assert.Equal(t, policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, OperatorIn)
	assert.Equal(t, policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN, OperatorNotIn)
	assert.Equal(t, policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS, OperatorInContains)
}

func TestBooleanConstants(t *testing.T) {
	assert.Equal(t, policyproto.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND, BooleanAnd)
	assert.Equal(t, policyproto.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR, BooleanOr)
}

func TestRuleConstants(t *testing.T) {
	assert.Equal(t, policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, RuleAllOf)
	assert.Equal(t, policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, RuleAnyOf)
	assert.Equal(t, policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, RuleHierarchy)
}

func TestStateConstants(t *testing.T) {
	assert.Equal(t, common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE, StateActive)
	assert.Equal(t, common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE, StateInactive)
	assert.Equal(t, common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY, StateAny)
}
