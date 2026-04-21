package namespacedpolicy

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteSubjectMappings(t *testing.T) {
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
			name: "creates subject mappings with migrated action and scs ids",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
				},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{
							Id: "scs-1",
						},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
				},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{
							Id: "mapping-1",
							AttributeValue: &policy.Value{
								Id: "av-1",
							},
							Metadata: &common.Metadata{
								Labels: map[string]string{
									"owner": "policy-team",
									"env":   "dev",
								},
							},
						},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
								Actions: []*ActionBinding{
									{
										SourceID:  "action-1",
										Namespace: namespace1,
										Status:    TargetStatusCreate,
									},
								},
								SubjectConditionSet: &SubjectConditionSetBinding{
									SourceID:  "scs-1",
									Namespace: namespace1,
									Status:    TargetStatusCreate,
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				results: map[string]map[string]*policy.Action{
					"decrypt": {
						"ns-1": {Id: "action-target-1"},
					},
				},
				subjectConditionSetResult: map[string]map[string]*policy.SubjectConditionSet{
					"scs-1": {
						"ns-1": {Id: "scs-target-1"},
					},
				},
				subjectMappingResults: map[string]map[string]*policy.SubjectMapping{
					"mapping-1": {
						"ns-1": {Id: "mapping-target-1"},
					},
				},
			},
			runID: "run-789",
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				require.Contains(t, handler.createdSubjectMappings, "mapping-1")
				require.Contains(t, handler.createdSubjectMappings["mapping-1"], "ns-1")
				call := handler.createdSubjectMappings["mapping-1"]["ns-1"]
				assert.Equal(t, "av-1", call.AttributeValueID)
				require.Len(t, call.Actions, 1)
				assert.Equal(t, "action-target-1", call.Actions[0].GetId())
				assert.Equal(t, "scs-target-1", call.ExistingSubjectConditionSet)
				assert.Nil(t, call.NewSubjectConditionSet)
				assert.Equal(t, "ns-1", call.Namespace)
				assert.Equal(t, map[string]string{
					"owner":                    "policy-team",
					"env":                      "dev",
					migrationLabelMigratedFrom: "mapping-1",
					migrationLabelRun:          "run-789",
				}, call.Metadata.GetLabels())

				target := plan.SubjectMappings[0].Targets[0]
				assert.Equal(t, TargetStatusCreate, target.Status)
				assert.Nil(t, target.Existing)
				require.NotNil(t, target.Execution)
				assert.True(t, target.Execution.Applied)
				assert.Equal(t, "mapping-target-1", target.Execution.CreatedTargetID)
				assert.Equal(t, "run-789", target.Execution.RunID)
				assert.Equal(t, "mapping-target-1", target.TargetID())
			},
		},
		{
			name: "skips already migrated subject mapping targets",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectMappings},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{Id: "mapping-1"},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.SubjectMapping{Id: "mapping-target-1"},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
				assert.Equal(t, "mapping-target-1", plan.SubjectMappings[0].Targets[0].TargetID())
				assert.Nil(t, plan.SubjectMappings[0].Targets[0].Execution)
			},
		},
		{
			name: "returns not executable for unresolved target status",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectMappings},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{Id: "mapping-1"},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusUnresolved,
								Reason:    "missing target namespace mapping",
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(
				ErrPlanNotExecutable,
				`subject mapping %q target %q is unresolved: %s`,
				"mapping-1",
				namespace1.GetFqn(),
				"missing target namespace mapping",
			),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
			},
		},
		{
			name: "returns error for missing already migrated target id",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectMappings},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{Id: "mapping-1"},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingMigratedTarget, `subject mapping %q target %q`, "mapping-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
			},
		},
		{
			name: "returns error for missing action target id",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectMappings},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{
							Id: "mapping-1",
							AttributeValue: &policy.Value{
								Id: "av-1",
							},
						},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
								Actions: []*ActionBinding{
									{
										SourceID:  "action-1",
										Namespace: namespace1,
										Status:    TargetStatusCreate,
									},
								},
								SubjectConditionSet: &SubjectConditionSetBinding{
									SourceID:  "scs-1",
									Namespace: namespace1,
									Status:    TargetStatusAlreadyMigrated,
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingActionTarget, `subject mapping %q action %q target %q`, "mapping-1", "action-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
			},
		},
		{
			name: "returns error for missing scs target id",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeSubjectMappings},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.Action{Id: "action-target-1"},
							},
						},
					},
				},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{
							Id: "mapping-1",
							AttributeValue: &policy.Value{
								Id: "av-1",
							},
						},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
								Actions: []*ActionBinding{
									{
										SourceID:  "action-1",
										Namespace: namespace1,
										Status:    TargetStatusAlreadyMigrated,
									},
								},
								SubjectConditionSet: &SubjectConditionSetBinding{
									SourceID:  "scs-1",
									Namespace: namespace1,
									Status:    TargetStatusCreate,
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingSubjectConditionSetTarget, `subject mapping %q subject condition set %q target %q`, "mapping-1", "scs-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
			},
		},
		{
			name: "returns error for missing target namespace",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectMappings},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{
							Id: "mapping-1",
							AttributeValue: &policy.Value{
								Id: "av-1",
							},
						},
						Targets: []*SubjectMappingTargetPlan{
							{
								Status: TargetStatusCreate,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrTargetNamespaceRequired, `subject mapping %q`, "mapping-1"),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
			},
		},
		{
			name: "returns error for missing created target id",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.Action{Id: "action-target-1"},
							},
						},
					},
				},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1"},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.SubjectConditionSet{Id: "scs-target-1"},
							},
						},
					},
				},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{
							Id: "mapping-1",
							AttributeValue: &policy.Value{
								Id: "av-1",
							},
						},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
								Actions: []*ActionBinding{
									{
										SourceID:  "action-1",
										Namespace: namespace1,
										Status:    TargetStatusAlreadyMigrated,
									},
								},
								SubjectConditionSet: &SubjectConditionSetBinding{
									SourceID:  "scs-1",
									Namespace: namespace1,
									Status:    TargetStatusAlreadyMigrated,
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				subjectMappingResults: map[string]map[string]*policy.SubjectMapping{
					"mapping-1": {
						"ns-1": {},
					},
				},
			},
			wantErr: wantError(ErrMissingCreatedTargetID, `subject mapping %q target %q`, "mapping-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdSubjectMappings, "mapping-1")
				require.NotNil(t, plan.SubjectMappings[0].Targets[0].Execution)
				assert.Equal(t, ErrMissingCreatedTargetID.Error(), plan.SubjectMappings[0].Targets[0].Execution.Failure)
			},
		},
		{
			name: "returns error for unsupported target status",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectMappings},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{Id: "mapping-1"},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatus("bogus"),
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(
				ErrUnsupportedStatus,
				`subject mapping %q target %q has unsupported status %q`,
				"mapping-1",
				namespace1.GetFqn(),
				TargetStatus("bogus"),
			),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectMappings)
			},
		},
		{
			name: "records create failures on the target",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.Action{Id: "action-target-1"},
							},
						},
					},
				},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1"},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.SubjectConditionSet{Id: "scs-target-1"},
							},
						},
					},
				},
				SubjectMappings: []*SubjectMappingPlan{
					{
						Source: &policy.SubjectMapping{
							Id: "mapping-1",
							AttributeValue: &policy.Value{
								Id: "av-1",
							},
						},
						Targets: []*SubjectMappingTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
								Actions: []*ActionBinding{
									{
										SourceID:  "action-1",
										Namespace: namespace1,
										Status:    TargetStatusAlreadyMigrated,
									},
								},
								SubjectConditionSet: &SubjectConditionSetBinding{
									SourceID:  "scs-1",
									Namespace: namespace1,
									Status:    TargetStatusAlreadyMigrated,
								},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				subjectMappingErrs: map[string]map[string]error{
					"mapping-1": {
						"ns-1": errBoom,
					},
				},
			},
			wantErr: &expectedError{
				is:      errBoom,
				message: `create subject mapping "mapping-1" in namespace "https://example.com": boom`,
			},
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdSubjectMappings, "mapping-1")
				require.NotNil(t, plan.SubjectMappings[0].Targets[0].Execution)
				assert.Equal(t, "boom", plan.SubjectMappings[0].Targets[0].Execution.Failure)
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

func TestSubjectMappingTargetIDPrefersExecutionResult(t *testing.T) {
	t.Parallel()

	target := &SubjectMappingTargetPlan{
		Namespace: &policy.Namespace{Id: "ns-2", Fqn: "https://example.net"},
		Existing:  &policy.SubjectMapping{Id: "existing-target"},
		Execution: &ExecutionResult{
			CreatedTargetID: "created-target",
		},
	}

	assert.Equal(t, "created-target", target.TargetID())
}
