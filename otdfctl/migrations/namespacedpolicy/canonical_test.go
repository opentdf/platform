package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestSortByJSONOrdersItemsByEncodedKey(t *testing.T) {
	t.Parallel()

	items := []struct {
		Name string `json:"name"`
	}{
		{Name: "b"},
		{Name: "c"},
		{Name: "a"},
	}

	sortByJSON(items)

	assert.Equal(t, []struct {
		Name string `json:"name"`
	}{
		{Name: "a"},
		{Name: "b"},
		{Name: "c"},
	}, items)
}

func TestCanonicalRegisteredResourceIgnoresValueAndBindingOrder(t *testing.T) {
	t.Parallel()

	left := testRegisteredResource(
		"resource-left",
		" Documents ",
		testRegisteredResourceValue(
			"Prod",
			testActionAttributeValue(
				"action-read",
				"Read",
				testAttributeValue("https://example.com/attr/classification/value/public", nil),
			),
			testActionAttributeValue(
				"action-write",
				"Write",
				testAttributeValue("https://example.com/attr/classification/value/internal", nil),
			),
		),
		testRegisteredResourceValue(
			"Dev",
			testActionAttributeValue(
				"action-read",
				"Read",
				testAttributeValue("https://example.com/attr/classification/value/public", nil),
			),
		),
	)
	right := testRegisteredResource(
		"resource-right",
		"documents",
		testRegisteredResourceValue(
			"dev",
			testActionAttributeValue(
				"action-read",
				"read",
				testAttributeValue("https://example.com/attr/classification/value/public", nil),
			),
		),
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				"action-write",
				"write",
				testAttributeValue("https://example.com/attr/classification/value/internal", nil),
			),
			testActionAttributeValue(
				"action-read",
				"read",
				testAttributeValue("https://example.com/attr/classification/value/public", nil),
			),
		),
	)

	assert.Equal(t, canonicalRegisteredResource(left), canonicalRegisteredResource(right))
	assert.True(t, registeredResourceCanonicalEqual(left, right))
}

func TestCanonicalSubjectConditionSetIgnoresOrderAtEveryLevel(t *testing.T) {
	t.Parallel()

	condA := &policy.Condition{
		SubjectExternalSelectorValue: ".department",
		Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectExternalValues:        []string{"engineering", "security"},
	}
	condB := &policy.Condition{
		SubjectExternalSelectorValue: ".role",
		Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectExternalValues:        []string{"admin"},
	}
	groupAB := &policy.ConditionGroup{
		Conditions:      []*policy.Condition{condA, condB},
		BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
	}
	groupBA := &policy.ConditionGroup{
		Conditions:      []*policy.Condition{condB, condA},
		BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
	}

	left := &policy.SubjectConditionSet{
		Id: "scs-left",
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{groupAB}},
			{ConditionGroups: []*policy.ConditionGroup{groupBA}},
		},
	}
	right := &policy.SubjectConditionSet{
		Id: "scs-right",
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{groupBA}},
			{ConditionGroups: []*policy.ConditionGroup{groupAB}},
		},
	}

	assert.Equal(t, canonicalSubjectConditionSet(left), canonicalSubjectConditionSet(right))
	assert.True(t, subjectConditionSetCanonicalEqual(left, right))
}

func TestCanonicalSubjectConditionSetSortsValuesWithinConditions(t *testing.T) {
	t.Parallel()

	left := &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".role",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"admin", "editor", "viewer"},
						},
					},
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				},
			}},
		},
	}
	right := &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".role",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"viewer", "admin", "editor"},
						},
					},
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				},
			}},
		},
	}

	assert.True(t, subjectConditionSetCanonicalEqual(left, right))
}

func TestCanonicalSubjectConditionSetDistinguishesDifferentConditions(t *testing.T) {
	t.Parallel()

	left := &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".role",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"admin"},
						},
					},
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				},
			}},
		},
	}
	right := &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".role",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"editor"},
						},
					},
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				},
			}},
		},
	}

	assert.False(t, subjectConditionSetCanonicalEqual(left, right))
}

func TestCanonicalSubjectConditionSetReturnsEmptyForNilOrEmpty(t *testing.T) {
	t.Parallel()

	assert.Empty(t, canonicalSubjectConditionSet(nil))
	assert.Empty(t, canonicalSubjectConditionSet(&policy.SubjectConditionSet{}))
	assert.Empty(t, canonicalSubjectConditionSet(&policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{nil},
	}))
}

func TestCanonicalObligationTriggerContextIgnoresOrder(t *testing.T) {
	t.Parallel()

	left := []*policy.RequestContext{
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "ingress-client"}},
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "egress-client"}},
	}
	right := []*policy.RequestContext{
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "egress-client"}},
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "ingress-client"}},
	}

	assert.Equal(t, canonicalObligationTriggerContext(left), canonicalObligationTriggerContext(right))
}

func TestCanonicalObligationTriggerContextSkipsNilEntries(t *testing.T) {
	t.Parallel()

	withNils := []*policy.RequestContext{
		nil,
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "client-a"}},
		{Pep: nil},
	}
	clean := []*policy.RequestContext{
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "client-a"}},
	}

	assert.Equal(t, canonicalObligationTriggerContext(withNils), canonicalObligationTriggerContext(clean))
}

func TestCanonicalObligationTriggerContextReturnsEmptyForNilOrEmpty(t *testing.T) {
	t.Parallel()

	assert.Empty(t, canonicalObligationTriggerContext(nil))
	assert.Empty(t, canonicalObligationTriggerContext([]*policy.RequestContext{}))
	assert.Empty(t, canonicalObligationTriggerContext([]*policy.RequestContext{nil}))
}

func TestCanonicalObligationTriggerIncludesContext(t *testing.T) {
	t.Parallel()

	base := &policy.ObligationTrigger{
		Action:         &policy.Action{Id: "action-1", Name: "decrypt"},
		AttributeValue: &policy.Value{Id: "value-1", Fqn: "https://attr.example.com/value/secret"},
		ObligationValue: &policy.ObligationValue{
			Id:  "ov-1",
			Fqn: "https://obligation.example.com/value/notify",
		},
	}

	left := protoCloneTrigger(base)
	left.Context = []*policy.RequestContext{
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "ingress-client"}},
	}

	right := protoCloneTrigger(base)
	right.Context = []*policy.RequestContext{
		{Pep: &policy.PolicyEnforcementPoint{ClientId: "egress-client"}},
	}

	assert.NotEqual(t, canonicalObligationTrigger(left), canonicalObligationTrigger(right))
}

func protoCloneTrigger(trigger *policy.ObligationTrigger) *policy.ObligationTrigger {
	if trigger == nil {
		return nil
	}

	return &policy.ObligationTrigger{
		Id:              trigger.GetId(),
		ObligationValue: trigger.GetObligationValue(),
		Action:          trigger.GetAction(),
		AttributeValue:  trigger.GetAttributeValue(),
		Metadata:        trigger.GetMetadata(),
	}
}
