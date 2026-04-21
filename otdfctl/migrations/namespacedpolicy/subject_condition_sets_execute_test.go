package namespacedpolicy

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteSubjectConditionSets(t *testing.T) {
	t.Parallel()

	namespace1 := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	namespace2 := &policy.Namespace{Id: "ns-2", Fqn: "https://example.net"}
	errBoom := errors.New("boom")
	subjectSets := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: "https://example.com/selector/role",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"admin"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		plan    *Plan
		handler *mockExecutorHandler
		runID   string
		wantErr *expectedError
		assert  func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan)
	}{
		{
			name: "handles created and already migrated subject condition set targets",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{
							Id:          "scs-1",
							SubjectSets: subjectSets,
							Metadata: &common.Metadata{
								Labels: map[string]string{
									"owner": "policy-team",
									"env":   "dev",
								},
							},
						},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
							{
								Namespace:  namespace2,
								Status:     TargetStatusAlreadyMigrated,
								ExistingID: "migrated-scs-1",
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				subjectConditionSetResult: map[string]map[string]*policy.SubjectConditionSet{
					"scs-1": {
						"ns-1": {Id: "created-scs-1"},
					},
				},
			},
			runID: "run-456",
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				require.Contains(t, handler.createdSubjectConditions, "scs-1")
				require.Contains(t, handler.createdSubjectConditions["scs-1"], "ns-1")
				assert.Len(t, handler.createdSubjectConditions["scs-1"], 1)
				assert.Equal(t, subjectSets, handler.createdSubjectConditions["scs-1"]["ns-1"].SubjectSets)
				assert.Equal(t, "ns-1", handler.createdSubjectConditions["scs-1"]["ns-1"].Namespace)
				assert.Equal(t, map[string]string{
					"owner":                    "policy-team",
					"env":                      "dev",
					migrationLabelMigratedFrom: "scs-1",
					migrationLabelRun:          "run-456",
				}, handler.createdSubjectConditions["scs-1"]["ns-1"].Metadata.GetLabels())

				createdTarget := plan.SubjectConditionSets[0].Targets[0]
				assert.Equal(t, TargetStatusCreate, createdTarget.Status)
				assert.Empty(t, createdTarget.ExistingID)
				require.NotNil(t, createdTarget.Execution)
				assert.True(t, createdTarget.Execution.Applied)
				assert.Equal(t, "created-scs-1", createdTarget.Execution.CreatedTargetID)
				assert.Equal(t, "run-456", createdTarget.Execution.RunID)
				assert.Equal(t, "created-scs-1", createdTarget.TargetID())

				migratedTarget := plan.SubjectConditionSets[0].Targets[1]
				assert.Equal(t, "migrated-scs-1", migratedTarget.TargetID())
				assert.Nil(t, migratedTarget.Execution)
				assert.Equal(t, "created-scs-1", executor.cachedScsTargetID("scs-1", namespace1))
				assert.Equal(t, "migrated-scs-1", executor.cachedScsTargetID("scs-1", namespace2))
				assert.Empty(t, executor.cachedScsTargetID("scs-2", namespace1))
			},
		},
		{
			name: "returns not executable for unresolved target status",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1"},
						Targets: []*SubjectConditionSetTargetPlan{
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
				`subject condition set %q target %q is unresolved: %s`,
				"scs-1",
				namespace1.GetFqn(),
				"missing target namespace mapping",
			),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectConditions)
			},
		},
		{
			name: "returns error for missing already migrated target id",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1"},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingMigratedTarget, `subject condition set %q target %q`, "scs-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectConditions)
			},
		},
		{
			name: "returns error for missing target namespace",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Status: TargetStatusCreate,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrTargetNamespaceRequired, `subject condition set %q`, "scs-1"),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectConditions)
			},
		},
		{
			name: "returns error for missing created target id",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				subjectConditionSetResult: map[string]map[string]*policy.SubjectConditionSet{
					"scs-1": {
						"ns-1": {},
					},
				},
			},
			wantErr: wantError(ErrMissingCreatedTargetID, `subject condition set %q target %q`, "scs-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdSubjectConditions, "scs-1")
				require.NotNil(t, plan.SubjectConditionSets[0].Targets[0].Execution)
				assert.Equal(t, ErrMissingCreatedTargetID.Error(), plan.SubjectConditionSets[0].Targets[0].Execution.Failure)
				assert.Empty(t, executor.cachedScsTargetID("scs-1", namespace1))
			},
		},
		{
			name: "returns error for unsupported target status",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1"},
						Targets: []*SubjectConditionSetTargetPlan{
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
				`subject condition set %q target %q has unsupported status %q`,
				"scs-1",
				namespace1.GetFqn(),
				TargetStatus("bogus"),
			),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdSubjectConditions)
			},
		},
		{
			name: "records create failures on the target",
			plan: &Plan{
				Scopes: []Scope{ScopeSubjectConditionSets},
				SubjectConditionSets: []*SubjectConditionSetPlan{
					{
						Source: &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets},
						Targets: []*SubjectConditionSetTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				subjectConditionSetErrs: map[string]map[string]error{
					"scs-1": {
						"ns-1": errBoom,
					},
				},
			},
			wantErr: &expectedError{
				is:      errBoom,
				message: `create subject condition set "scs-1" in namespace "https://example.com": boom`,
			},
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.NotNil(t, plan.SubjectConditionSets[0].Targets[0].Execution)
				assert.Equal(t, "boom", plan.SubjectConditionSets[0].Targets[0].Execution.Failure)
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
