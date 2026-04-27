package policy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	policyproto "github.com/opentdf/platform/protocol/go/policy"
)

func TestOperatorConstants(t *testing.T) {
	if OperatorIn != policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN {
		t.Errorf("OperatorIn = %d, want %d", OperatorIn, policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN)
	}
	if OperatorNotIn != policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN {
		t.Errorf("OperatorNotIn = %d, want %d", OperatorNotIn, policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN)
	}
	if OperatorInContains != policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS {
		t.Errorf("OperatorInContains = %d, want %d", OperatorInContains, policyproto.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS)
	}
}

func TestBooleanConstants(t *testing.T) {
	if BooleanAnd != policyproto.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND {
		t.Errorf("BooleanAnd = %d, want %d", BooleanAnd, policyproto.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND)
	}
	if BooleanOr != policyproto.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR {
		t.Errorf("BooleanOr = %d, want %d", BooleanOr, policyproto.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR)
	}
}

func TestRuleConstants(t *testing.T) {
	if RuleAllOf != policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF {
		t.Errorf("RuleAllOf = %d, want %d", RuleAllOf, policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)
	}
	if RuleAnyOf != policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF {
		t.Errorf("RuleAnyOf = %d, want %d", RuleAnyOf, policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	}
	if RuleHierarchy != policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		t.Errorf("RuleHierarchy = %d, want %d", RuleHierarchy, policyproto.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY)
	}
}

func TestStateConstants(t *testing.T) {
	if StateActive != common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE {
		t.Errorf("StateActive = %d, want %d", StateActive, common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE)
	}
	if StateInactive != common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE {
		t.Errorf("StateInactive = %d, want %d", StateInactive, common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE)
	}
	if StateAny != common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY {
		t.Errorf("StateAny = %d, want %d", StateAny, common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY)
	}
}
