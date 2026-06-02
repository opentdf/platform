package dynamicentitlement

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
	smbuiltin "github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
)

// ResourceValuePlaceholder is the sentinel an admin places in a reused
// policy.Condition.subject_external_values list to signal that the right-hand operand is
// the resource value segment rather than a static value.
//
// The fact that a sentinel is REQUIRED is itself a spike finding: the existing
// SubjectConditionSet schema has nowhere to express "this condition is dynamic", so
// Option A must overload an existing field. See ADR 0005.
const ResourceValuePlaceholder = "${resource.value}"

// DefinitionScopedSubjectMapping is Option A — "reuse Subject Mappings". It is the
// existing policy.SubjectConditionSet primitive re-scoped from an AttributeValue to an
// AttributeDefinition. It genuinely reuses the existing evaluator: static conditions go
// through subjectmappingbuiltin.EvaluateCondition unchanged, while a condition whose
// subject_external_values contains ResourceValuePlaceholder is routed to the shared
// dynamic core. The AND/OR subject-set / condition-group walk mirrors
// subjectmappingbuiltin.EvaluateSubjectSet.
//
// This shape supports mixed static + dynamic conditions, but at the cost of the sentinel
// overload above and a near-duplicate group walk (the production walk is hard-wired to
// the static leaf evaluator) — both captured as findings.
type DefinitionScopedSubjectMapping struct {
	// AttributeDefinitionFQN is the parent definition this mapping is scoped to.
	AttributeDefinitionFQN string
	// SubjectConditionSet is the reused, unmodified policy primitive.
	SubjectConditionSet *policy.SubjectConditionSet
	// Operator is the dynamic operator applied to placeholder conditions. When
	// OperatorUnspecified, it is derived from each placeholder condition's static
	// SubjectMappingOperatorEnum (IN -> ResourceValueIn, IN_CONTAINS -> ResourceValueInContains).
	Operator DynamicOperator
	// Actions are granted when the condition set matches.
	Actions []*policy.Action
	// Canonicalizer optionally overrides DefaultCanonicalizer.
	Canonicalizer Canonicalizer
}

var _ Mapping = (*DefinitionScopedSubjectMapping)(nil)

// DefinitionFQN implements Mapping.
func (m *DefinitionScopedSubjectMapping) DefinitionFQN() string {
	return strings.ToLower(m.AttributeDefinitionFQN)
}

// EntitledActions implements Mapping. Subject sets AND together (mirroring
// subjectmappingbuiltin.EvaluateSubjectMappings); on full match the mapped actions are
// returned.
func (m *DefinitionScopedSubjectMapping) EntitledActions(entity flattening.Flattened, segment string) ([]*policy.Action, error) {
	scs := m.SubjectConditionSet
	if scs == nil {
		return nil, nil
	}
	for _, ss := range scs.GetSubjectSets() {
		ok, err := m.evaluateSubjectSet(ss, entity, segment)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
	}
	return m.Actions, nil
}

func (m *DefinitionScopedSubjectMapping) evaluateSubjectSet(ss *policy.SubjectSet, entity flattening.Flattened, segment string) (bool, error) {
	// condition groups AND together
	for _, cg := range ss.GetConditionGroups() {
		ok, err := m.evaluateConditionGroup(cg, entity, segment)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func (m *DefinitionScopedSubjectMapping) evaluateConditionGroup(cg *policy.ConditionGroup, entity flattening.Flattened, segment string) (bool, error) {
	switch cg.GetBooleanOperator() {
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND:
		for _, c := range cg.GetConditions() {
			ok, err := m.evaluateCondition(c, entity, segment)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR:
		for _, c := range cg.GetConditions() {
			ok, err := m.evaluateCondition(c, entity, segment)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED:
		return false, errors.New("unspecified condition group boolean operator")
	default:
		return false, fmt.Errorf("unsupported condition group boolean operator: %s", cg.GetBooleanOperator())
	}
}

// evaluateCondition routes dynamic (placeholder) conditions to the shared core and
// static conditions to the existing, reused leaf evaluator.
func (m *DefinitionScopedSubjectMapping) evaluateCondition(c *policy.Condition, entity flattening.Flattened, segment string) (bool, error) {
	if !conditionIsDynamic(c) {
		return smbuiltin.EvaluateCondition(c, entity)
	}
	op := m.Operator
	if op == OperatorUnspecified {
		op = dynamicFromStatic(c.GetOperator())
	}
	return evaluateDynamicMatch(op, entity, c.GetSubjectExternalSelectorValue(), segment, m.Canonicalizer)
}

func conditionIsDynamic(c *policy.Condition) bool {
	for _, v := range c.GetSubjectExternalValues() {
		if v == ResourceValuePlaceholder {
			return true
		}
	}
	return false
}

// dynamicFromStatic maps a static SubjectMappingOperatorEnum to its dynamic inversion.
func dynamicFromStatic(op policy.SubjectMappingOperatorEnum) DynamicOperator {
	switch op {
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
		return ResourceValueIn
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
		return ResourceValueInContains
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
		policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED:
		return OperatorUnspecified
	default:
		return OperatorUnspecified
	}
}
