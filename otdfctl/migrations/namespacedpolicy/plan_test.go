package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceFromAttributeValueFallsBackToValueFQN(t *testing.T) {
	t.Parallel()

	namespace := namespaceFromAttributeValue(&policy.Value{
		Fqn: "https://example.com/attr/classification/value/secret",
	})
	require.NotNil(t, namespace)
	assert.Equal(t, "https://example.com", namespace.GetFqn())
}

func TestPlanLookupActionTarget(t *testing.T) {
	t.Parallel()

	nsA := &policy.Namespace{Id: "ns-a"}
	nsB := &policy.Namespace{Id: "ns-b"}
	targetA := &ActionTargetPlan{Namespace: nsA, Status: TargetStatusCreate}
	targetB := &ActionTargetPlan{Namespace: nsB, Status: TargetStatusCreate}

	plan := &Plan{
		Actions: []*ActionPlan{
			nil,
			{Source: nil, Targets: []*ActionTargetPlan{targetA}},
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					nil,
					{Namespace: nil},
					targetA,
					targetB,
				},
			},
		},
	}

	tests := []struct {
		name        string
		plan        *Plan
		sourceID    string
		namespaceID string
		want        *ActionTargetPlan
	}{
		{name: "nil plan", plan: nil, sourceID: "action-1", namespaceID: "ns-a", want: nil},
		{name: "empty sourceID", plan: plan, sourceID: "", namespaceID: "ns-a", want: nil},
		{name: "empty namespaceID", plan: plan, sourceID: "action-1", namespaceID: "", want: nil},
		{name: "match in namespace a", plan: plan, sourceID: "action-1", namespaceID: "ns-a", want: targetA},
		{name: "match in namespace b", plan: plan, sourceID: "action-1", namespaceID: "ns-b", want: targetB},
		{name: "unknown sourceID returns nil", plan: plan, sourceID: "action-missing", namespaceID: "ns-a", want: nil},
		{name: "unknown namespaceID returns nil", plan: plan, sourceID: "action-1", namespaceID: "ns-missing", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Same(t, tc.want, tc.plan.LookupActionTarget(tc.sourceID, tc.namespaceID))
		})
	}
}

func TestPlanLookupSubjectConditionSetTarget(t *testing.T) {
	t.Parallel()

	nsA := &policy.Namespace{Id: "ns-a"}
	nsB := &policy.Namespace{Id: "ns-b"}
	targetA := &SubjectConditionSetTargetPlan{Namespace: nsA, Status: TargetStatusCreate}
	targetB := &SubjectConditionSetTargetPlan{Namespace: nsB, Status: TargetStatusCreate}

	plan := &Plan{
		SubjectConditionSets: []*SubjectConditionSetPlan{
			nil,
			{Source: nil, Targets: []*SubjectConditionSetTargetPlan{targetA}},
			{
				Source: &policy.SubjectConditionSet{Id: "scs-1"},
				Targets: []*SubjectConditionSetTargetPlan{
					nil,
					{Namespace: nil},
					targetA,
					targetB,
				},
			},
		},
	}

	tests := []struct {
		name        string
		plan        *Plan
		sourceID    string
		namespaceID string
		want        *SubjectConditionSetTargetPlan
	}{
		{name: "nil plan", plan: nil, sourceID: "scs-1", namespaceID: "ns-a", want: nil},
		{name: "empty sourceID", plan: plan, sourceID: "", namespaceID: "ns-a", want: nil},
		{name: "empty namespaceID", plan: plan, sourceID: "scs-1", namespaceID: "", want: nil},
		{name: "match in namespace a", plan: plan, sourceID: "scs-1", namespaceID: "ns-a", want: targetA},
		{name: "match in namespace b", plan: plan, sourceID: "scs-1", namespaceID: "ns-b", want: targetB},
		{name: "unknown sourceID returns nil", plan: plan, sourceID: "scs-missing", namespaceID: "ns-a", want: nil},
		{name: "unknown namespaceID returns nil", plan: plan, sourceID: "scs-1", namespaceID: "ns-missing", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Same(t, tc.want, tc.plan.LookupSubjectConditionSetTarget(tc.sourceID, tc.namespaceID))
		})
	}
}
