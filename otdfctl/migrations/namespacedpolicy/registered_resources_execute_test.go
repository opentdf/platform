package namespacedpolicy

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteRegisteredResources(t *testing.T) {
	t.Parallel()

	namespace1 := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	errBoom := errors.New("boom")

	tests := []struct {
		name    string
		plan    *Plan
		handler *mockExecutorHandler
		runID   string
		wantErr *expectedError
		assert  func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan)
	}{
		{
			name: "creates registered resource shell and values with authoritative action target ids",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "read"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
					{
						Source: &policy.Action{Id: "action-2", Name: "standard-read"},
						Targets: []*ActionTargetPlan{
							{
								Namespace:  namespace1,
								Status:     TargetStatusExistingStandard,
								ExistingID: "existing-standard-action-2",
							},
						},
					},
				},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{
							Id:   "rr-1",
							Name: "repo",
							Metadata: &common.Metadata{
								Labels: map[string]string{
									"owner": "policy-team",
								},
							},
						},
						Target: &RegisteredResourceTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusCreate,
							Values: []*RegisteredResourceValuePlan{
								{
									Source: &policy.RegisteredResourceValue{
										Id:    "rrv-1",
										Value: "repo-a",
										Metadata: &common.Metadata{
											Labels: map[string]string{
												"classification": "secret",
											},
										},
									},
									ActionBindings: []*RegisteredResourceActionBinding{
										{
											SourceActionID: "action-1",
											AttributeValue: &policy.Value{
												Id:  "attribute-value-id-1",
												Fqn: "https://example.com/attr/classification/value/secret",
											},
										},
										{
											SourceActionID: "action-2",
											AttributeValue: &policy.Value{
												Fqn: "https://example.com/attr/project/value/apollo",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				results: map[string]map[string]*policy.Action{
					"read": {
						"ns-1": {Id: "created-action-1", Name: "read"},
					},
				},
				registeredResourceResult: map[string]map[string]*policy.RegisteredResource{
					"rr-1": {
						"ns-1": {Id: "created-rr-1", Name: "repo"},
					},
				},
				registeredResourceValueResult: map[string]map[string]*policy.RegisteredResourceValue{
					"rrv-1": {
						"created-rr-1": {Id: "created-rrv-1", Value: "repo-a"},
					},
				},
			},
			runID: "run-rr-123",
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)

				require.Contains(t, handler.createdRegisteredResources, "rr-1")
				require.Contains(t, handler.createdRegisteredResources["rr-1"], "ns-1")
				resourceCall := handler.createdRegisteredResources["rr-1"]["ns-1"]
				assert.Equal(t, "repo", resourceCall.Name)
				assert.Equal(t, "ns-1", resourceCall.Namespace)
				assert.Empty(t, resourceCall.Values)
				assert.Equal(t, map[string]string{
					"owner":                    "policy-team",
					migrationLabelMigratedFrom: "rr-1",
					migrationLabelRun:          "run-rr-123",
				}, resourceCall.Metadata.GetLabels())

				require.Contains(t, handler.createdRegisteredResourceValues, "rrv-1")
				require.Contains(t, handler.createdRegisteredResourceValues["rrv-1"], "created-rr-1")
				valueCall := handler.createdRegisteredResourceValues["rrv-1"]["created-rr-1"]
				assert.Equal(t, "created-rr-1", valueCall.ResourceID)
				assert.Equal(t, "repo-a", valueCall.Value)
				assert.Equal(t, map[string]string{
					"classification":           "secret",
					migrationLabelMigratedFrom: "rrv-1",
					migrationLabelRun:          "run-rr-123",
				}, valueCall.Metadata.GetLabels())
				require.Len(t, valueCall.ActionAttributeValues, 2)
				assert.Equal(t, "created-action-1", valueCall.ActionAttributeValues[0].GetActionId())
				assert.Equal(t, "attribute-value-id-1", valueCall.ActionAttributeValues[0].GetAttributeValueId())
				assert.Equal(t, "existing-standard-action-2", valueCall.ActionAttributeValues[1].GetActionId())
				assert.Equal(t, "https://example.com/attr/project/value/apollo", valueCall.ActionAttributeValues[1].GetAttributeValueFqn())

				resourceTarget := plan.RegisteredResources[0].Target
				require.NotNil(t, resourceTarget.Execution)
				assert.True(t, resourceTarget.Execution.Applied)
				assert.Equal(t, "created-rr-1", resourceTarget.Execution.CreatedTargetID)
				assert.Equal(t, "run-rr-123", resourceTarget.Execution.RunID)
				assert.Equal(t, "created-rr-1", resourceTarget.TargetID())

				valueTarget := plan.RegisteredResources[0].Target.Values[0]
				require.NotNil(t, valueTarget.Execution)
				assert.True(t, valueTarget.Execution.Applied)
				assert.Equal(t, "created-rrv-1", valueTarget.Execution.CreatedTargetID)
				assert.Equal(t, "run-rr-123", valueTarget.Execution.RunID)
				assert.Equal(t, "created-rrv-1", valueTarget.TargetID())

				assert.Equal(t, "created-action-1", executor.cachedActionTargetID("action-1", namespace1))
				assert.Equal(t, "existing-standard-action-2", executor.cachedActionTargetID("action-2", namespace1))
			},
		},
		{
			name: "skips already migrated registered resource targets",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{Id: "rr-1", Name: "repo"},
						Target: &RegisteredResourceTargetPlan{
							Namespace:  namespace1,
							Status:     TargetStatusAlreadyMigrated,
							ExistingID: "migrated-rr-1",
							Values: []*RegisteredResourceValuePlan{
								{
									Source: &policy.RegisteredResourceValue{Id: "rrv-1", Value: "repo-a"},
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, handler.createdRegisteredResources)
				assert.Nil(t, handler.createdRegisteredResourceValues)
				assert.Equal(t, "migrated-rr-1", plan.RegisteredResources[0].Target.TargetID())
				assert.Nil(t, plan.RegisteredResources[0].Target.Execution)
				assert.Nil(t, plan.RegisteredResources[0].Target.Values[0].Execution)
			},
		},
		{
			name: "returns not executable for unresolved target status",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{Id: "rr-1", Name: "repo"},
						Target: &RegisteredResourceTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusUnresolved,
							Reason:    ErrDuplicateCanonicalMatch.Error(),
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(
				ErrPlanNotExecutable,
				`registered resource %q target %q is unresolved: %s`,
				"rr-1",
				namespace1.GetFqn(),
				ErrDuplicateCanonicalMatch,
			),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, handler.createdRegisteredResources)
				assert.Nil(t, handler.createdRegisteredResourceValues)
			},
		},
		{
			name: "reuses existing registered resource parent on create targets",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "read"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
				},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{Id: "rr-1", Name: "repo"},
						Target: &RegisteredResourceTargetPlan{
							Namespace:  namespace1,
							Status:     TargetStatusCreate,
							ExistingID: "existing-rr-1",
							Values: []*RegisteredResourceValuePlan{
								{
									Source: &policy.RegisteredResourceValue{Id: "rrv-1", Value: "repo-a"},
									ActionBindings: []*RegisteredResourceActionBinding{
										{
											SourceActionID: "action-1",
											AttributeValue: &policy.Value{Id: "attribute-value-id-1"},
										},
									},
								},
								{
									Source: &policy.RegisteredResourceValue{Id: "rrv-2", Value: "repo-b"},
									ActionBindings: []*RegisteredResourceActionBinding{
										{
											SourceActionID: "action-1",
											AttributeValue: &policy.Value{Id: "attribute-value-id-2"},
										},
									},
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				results: map[string]map[string]*policy.Action{
					"read": {
						"ns-1": {Id: "created-action-1", Name: "read"},
					},
				},
				registeredResourceValueResult: map[string]map[string]*policy.RegisteredResourceValue{
					"rrv-2": {
						"existing-rr-1": {Id: "created-rrv-2", Value: "repo-b"},
					},
				},
				registeredResourcesByID: map[string]*policy.RegisteredResource{
					"existing-rr-1": {
						Id:   "existing-rr-1",
						Name: "repo",
						Values: []*policy.RegisteredResourceValue{
							{Id: "existing-rrv-1", Value: "repo-a"},
						},
					},
				},
			},
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, handler.createdRegisteredResources)
				require.Contains(t, handler.createdRegisteredResourceValues, "rrv-2")
				require.Contains(t, handler.createdRegisteredResourceValues["rrv-2"], "existing-rr-1")
				assert.NotContains(t, handler.createdRegisteredResourceValues, "rrv-1")

				target := plan.RegisteredResources[0].Target
				require.NotNil(t, target.Execution)
				assert.True(t, target.Execution.Applied)
				assert.Equal(t, "existing-rr-1", target.Execution.CreatedTargetID)
				assert.Equal(t, "existing-rr-1", target.TargetID())

				existingValue := target.Values[0]
				require.NotNil(t, existingValue.Execution)
				assert.True(t, existingValue.Execution.Applied)
				assert.Equal(t, "existing-rrv-1", existingValue.Execution.CreatedTargetID)

				createdValue := target.Values[1]
				require.NotNil(t, createdValue.Execution)
				assert.True(t, createdValue.Execution.Applied)
				assert.Equal(t, "created-rrv-2", createdValue.Execution.CreatedTargetID)
			},
		},
		{
			name: "records shell creation failures on the target",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{Id: "rr-1", Name: "repo"},
						Target: &RegisteredResourceTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusCreate,
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				registeredResourceErrs: map[string]map[string]error{
					"rr-1": {
						"ns-1": errBoom,
					},
				},
			},
			wantErr: wantError(errBoom, `create registered resource %q in namespace %q`, "rr-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdRegisteredResources, "rr-1")
				require.NotNil(t, plan.RegisteredResources[0].Target.Execution)
				assert.Equal(t, "boom", plan.RegisteredResources[0].Target.Execution.Failure)
			},
		},
		{
			name: "stops when a registered resource value cannot resolve its migrated action target",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{Id: "rr-1", Name: "repo"},
						Target: &RegisteredResourceTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusCreate,
							Values: []*RegisteredResourceValuePlan{
								{
									Source: &policy.RegisteredResourceValue{Id: "rrv-1", Value: "repo-a"},
									ActionBindings: []*RegisteredResourceActionBinding{
										{
											SourceActionID: "missing-action",
											AttributeValue: &policy.Value{Id: "attribute-value-id-1"},
										},
									},
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				registeredResourceResult: map[string]map[string]*policy.RegisteredResource{
					"rr-1": {
						"ns-1": {Id: "created-rr-1", Name: "repo"},
					},
				},
			},
			wantErr: wantError(
				ErrMissingMigratedTarget,
				`action %q target %q: build registered resource value %q action bindings for namespace %q`,
				"missing-action",
				namespace1.GetFqn(),
				"rrv-1",
				namespace1.GetFqn(),
			),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdRegisteredResources, "rr-1")
				assert.Nil(t, handler.createdRegisteredResourceValues)
				require.NotNil(t, plan.RegisteredResources[0].Target.Execution)
				assert.True(t, plan.RegisteredResources[0].Target.Execution.Applied)
				require.NotNil(t, plan.RegisteredResources[0].Target.Values[0].Execution)
				assert.Contains(t, plan.RegisteredResources[0].Target.Values[0].Execution.Failure, `missing migrated target: action "missing-action" target "https://example.com"`)
			},
		},
		{
			name: "records value creation failures on the value target",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "read"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
				},
				RegisteredResources: []*RegisteredResourcePlan{
					{
						Source: &policy.RegisteredResource{Id: "rr-1", Name: "repo"},
						Target: &RegisteredResourceTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusCreate,
							Values: []*RegisteredResourceValuePlan{
								{
									Source: &policy.RegisteredResourceValue{Id: "rrv-1", Value: "repo-a"},
									ActionBindings: []*RegisteredResourceActionBinding{
										{
											SourceActionID: "action-1",
											AttributeValue: &policy.Value{Id: "attribute-value-id-1"},
										},
									},
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				results: map[string]map[string]*policy.Action{
					"read": {
						"ns-1": {Id: "created-action-1", Name: "read"},
					},
				},
				registeredResourceResult: map[string]map[string]*policy.RegisteredResource{
					"rr-1": {
						"ns-1": {Id: "created-rr-1", Name: "repo"},
					},
				},
				registeredResourceValueErrs: map[string]map[string]error{
					"rrv-1": {
						"created-rr-1": errBoom,
					},
				},
			},
			wantErr: wantError(errBoom, `create registered resource value %q for resource %q in namespace %q`, "rrv-1", "created-rr-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdRegisteredResourceValues, "rrv-1")
				require.NotNil(t, plan.RegisteredResources[0].Target.Execution)
				assert.True(t, plan.RegisteredResources[0].Target.Execution.Applied)
				require.NotNil(t, plan.RegisteredResources[0].Target.Values[0].Execution)
				assert.Equal(t, "boom", plan.RegisteredResources[0].Target.Values[0].Execution.Failure)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			executor, err := NewExecutor(tt.handler)
			require.NoError(t, err)
			if tt.runID != "" {
				executor.runID = tt.runID
			}

			err = executor.Execute(t.Context(), tt.plan)
			switch {
			case tt.wantErr != nil:
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr.is)
				require.EqualError(t, err, tt.wantErr.message)
			default:
				require.NoError(t, err)
			}

			tt.assert(t, err, executor, tt.handler, tt.plan)
		})
	}
}
