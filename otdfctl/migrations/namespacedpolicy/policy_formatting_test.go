package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestPlainPolicyActionNamesSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actions []*policy.Action
		want    string
	}{
		{name: "empty", want: noneLabel},
		{
			name: "skips nil and deduplicates labels",
			actions: []*policy.Action{
				nil,
				{Id: "action-1", Name: "read"},
				{Id: "action-2", Name: "write"},
				{Id: "action-3", Name: "read"},
			},
			want: `"read", "write"`,
		},
		{
			name: "falls back to id",
			actions: []*policy.Action{
				{Id: "action-1"},
			},
			want: `"action-1"`,
		},
		{
			name: "ignores empty labels",
			actions: []*policy.Action{
				{},
			},
			want: noneLabel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, plainPolicyActionNamesSummary(tc.actions))
		})
	}
}

func TestPlainRegisteredResourceSourceSummary(t *testing.T) {
	t.Parallel()

	secretValue := testAttributeValue("https://example.com/attr/classification/value/secret", testNamespace("https://example.com"))

	tests := []struct {
		name     string
		resource *policy.RegisteredResource
		want     string
	}{
		{name: "nil", want: "values=(none) (action_bindings=(none))"},
		{
			name:     "empty values",
			resource: &policy.RegisteredResource{},
			want:     "values=(none) (action_bindings=(none))",
		},
		{
			name: "deduplicates values and bindings",
			resource: testRegisteredResource(
				"resource-1",
				"dataset",
				testRegisteredResourceValue("prod", testActionAttributeValue("action-1", "read", secretValue)),
				testRegisteredResourceValue("prod", testActionAttributeValue("action-1", "read", secretValue)),
				testRegisteredResourceValue("dev", testActionAttributeValue("action-2", "write", secretValue)),
			),
			want: `values="prod", "dev" (action_bindings="read" -> https://example.com/attr/classification/value/secret, "write" -> https://example.com/attr/classification/value/secret)`,
		},
		{
			name: "value falls back to id",
			resource: testRegisteredResource(
				"resource-1",
				"dataset",
				&policy.RegisteredResourceValue{Id: "value-1"},
			),
			want: `values="value-1" (action_bindings=(none))`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, plainRegisteredResourceSourceSummary(tc.resource))
		})
	}
}

func TestObligationLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		obligation *policy.Obligation
		want       string
	}{
		{name: "nil", want: noneLabel},
		{
			name: "uses fqn first",
			obligation: &policy.Obligation{
				Id:   "obligation-1",
				Name: "watermark",
				Fqn:  "https://example.com/obl/watermark",
			},
			want: "https://example.com/obl/watermark",
		},
		{
			name: "falls back to name",
			obligation: &policy.Obligation{
				Id:   "obligation-1",
				Name: "watermark",
			},
			want: "watermark",
		},
		{
			name: "falls back to id",
			obligation: &policy.Obligation{
				Id: "obligation-1",
			},
			want: "obligation-1",
		},
		{
			name:       "empty",
			obligation: &policy.Obligation{},
			want:       noneLabel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, obligationLabel(tc.obligation))
		})
	}
}

func TestPlainRequestContextsSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		contexts []*policy.RequestContext
		want     string
	}{
		{name: "empty", want: noneLabel},
		{
			name: "skips empty and deduplicates client ids",
			contexts: []*policy.RequestContext{
				nil,
				{},
				{Pep: &policy.PolicyEnforcementPoint{}},
				{Pep: &policy.PolicyEnforcementPoint{ClientId: "tdf-client"}},
				{Pep: &policy.PolicyEnforcementPoint{ClientId: "tdf-client"}},
				{Pep: &policy.PolicyEnforcementPoint{ClientId: "admin-client"}},
			},
			want: `client_id="tdf-client", client_id="admin-client"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, plainRequestContextsSummary(tc.contexts))
		})
	}
}
