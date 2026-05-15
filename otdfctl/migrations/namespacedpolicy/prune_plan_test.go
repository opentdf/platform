package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestTargetRefString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target TargetRef
		want   string
	}{
		{name: "empty", target: TargetRef{}, want: noneLabel},
		{
			name: "id only",
			target: TargetRef{
				ID: "target-1",
			},
			want: `id: "target-1"`,
		},
		{
			name: "id with namespace id",
			target: TargetRef{
				ID:          "target-1",
				NamespaceID: "namespace-1",
			},
			want: `id: "target-1" namespace: "namespace-1"`,
		},
		{
			name: "id with namespace fqn",
			target: TargetRef{
				ID:           "target-1",
				NamespaceID:  "namespace-1",
				NamespaceFQN: "https://example.com",
			},
			want: `id: "target-1" namespace: "https://example.com"`,
		},
		{
			name: "namespace without id",
			target: TargetRef{
				NamespaceFQN: "https://example.com",
			},
			want: `namespace: "https://example.com"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.target.String())
		})
	}
}

func TestPrunePlanItemSourceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		item prunePlanItem
		want string
	}{
		{
			name: "action",
			item: &PruneActionPlan{Source: &policy.Action{Id: "action-1"}},
			want: "action-1",
		},
		{
			name: "action without source",
			item: &PruneActionPlan{},
			want: "",
		},
		{
			name: "nil action plan",
			item: (*PruneActionPlan)(nil),
			want: "",
		},
		{
			name: "subject condition set",
			item: &PruneSubjectConditionSetPlan{Source: &policy.SubjectConditionSet{Id: "scs-1"}},
			want: "scs-1",
		},
		{
			name: "subject condition set without source",
			item: &PruneSubjectConditionSetPlan{},
			want: "",
		},
		{
			name: "nil subject condition set plan",
			item: (*PruneSubjectConditionSetPlan)(nil),
			want: "",
		},
		{
			name: "subject mapping",
			item: &PruneSubjectMappingPlan{Source: &policy.SubjectMapping{Id: "mapping-1"}},
			want: "mapping-1",
		},
		{
			name: "subject mapping without source",
			item: &PruneSubjectMappingPlan{},
			want: "",
		},
		{
			name: "nil subject mapping plan",
			item: (*PruneSubjectMappingPlan)(nil),
			want: "",
		},
		{
			name: "registered resource",
			item: &PruneRegisteredResourcePlan{Source: &policy.RegisteredResource{Id: "resource-1"}},
			want: "resource-1",
		},
		{
			name: "registered resource without source",
			item: &PruneRegisteredResourcePlan{},
			want: "",
		},
		{
			name: "nil registered resource plan",
			item: (*PruneRegisteredResourcePlan)(nil),
			want: "",
		},
		{
			name: "obligation trigger",
			item: &PruneObligationTriggerPlan{Source: &policy.ObligationTrigger{Id: "trigger-1"}},
			want: "trigger-1",
		},
		{
			name: "obligation trigger without source",
			item: &PruneObligationTriggerPlan{},
			want: "",
		},
		{
			name: "nil obligation trigger plan",
			item: (*PruneObligationTriggerPlan)(nil),
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.item.sourceID())
		})
	}
}
