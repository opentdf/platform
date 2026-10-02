package policy

import (
	"github.com/opentdf/platform/protocol/go/common"
	policy "github.com/opentdf/platform/protocol/go/policy"
)

// Shorthand constants for SubjectMappingOperatorEnum.
//
// Example:
//
//	condition := &policy.Condition{
//	    SubjectExternalSelectorValue: ".email",
//	    Operator:                     policy.OperatorInContains,
//	    SubjectExternalValues:        []string{"@example.com"},
//	}
const (
	OperatorIn         = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN
	OperatorNotIn      = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN
	OperatorInContains = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS
)

// Shorthand constants for ConditionBooleanTypeEnum.
//
// Example:
//
//	group := &policy.ConditionGroup{
//	    BooleanOperator: policy.BooleanAnd,
//	    Conditions:      conditions,
//	}
const (
	BooleanAnd = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND
	BooleanOr  = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR
)

// Shorthand constants for AttributeRuleTypeEnum.
//
// Example:
//
//	req := &attributes.CreateAttributeRequest{
//	    Name: "clearance",
//	    Rule: policy.RuleHierarchy,
//	}
const (
	RuleAllOf     = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
	RuleAnyOf     = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF
	RuleHierarchy = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY
)

// Shorthand constants for ActiveStateEnum (from the common package).
//
// Example:
//
//	req := &attributes.ListAttributesRequest{
//	    State: policy.StateActive,
//	}
const (
	StateActive   = common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE
	StateInactive = common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE
	StateAny      = common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY
)
