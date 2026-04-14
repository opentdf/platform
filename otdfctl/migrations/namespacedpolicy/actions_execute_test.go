package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteActions(t *testing.T) {
	t.Parallel()

	namespace1 := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	namespace2 := &policy.Namespace{Id: "ns-2", Fqn: "https://example.net"}
	namespace3 := &policy.Namespace{Id: "ns-3", Fqn: "https://example.org"}

	tests := []struct {
		name    string
		plan    *Plan
		handler *mockExecutorHandler
		runID   string
		wantErr *expectedError
		assert  func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan)
	}{
		{
			name: "handles created, existing, and already migrated action targets",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{
							Id:   "action-1",
							Name: "decrypt",
							Metadata: &common.Metadata{
								Labels: map[string]string{
									"owner": "policy-team",
									"env":   "dev",
								},
							},
						},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
							{
								Namespace: namespace2,
								Status:    TargetStatusExistingStandard,
								Existing:  &policy.Action{Id: "standard-action"},
							},
							{
								Namespace: namespace3,
								Status:    TargetStatusAlreadyMigrated,
								Existing:  &policy.Action{Id: "migrated-action"},
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{
				results: map[string]map[string]*policy.Action{
					"decrypt": {
						"ns-1": {Id: "created-action-1", Name: "decrypt"},
					},
				},
			},
			runID: "run-123",
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				require.Contains(t, handler.created, "decrypt")
				require.Contains(t, handler.created["decrypt"], "ns-1")
				assert.Len(t, handler.created["decrypt"], 1)
				assert.Equal(t, "decrypt", handler.created["decrypt"]["ns-1"].Name)
				assert.Equal(t, "ns-1", handler.created["decrypt"]["ns-1"].Namespace)
				assert.Equal(t, map[string]string{
					"owner":                    "policy-team",
					"env":                      "dev",
					migrationLabelMigratedFrom: "action-1",
					migrationLabelRun:          "run-123",
				}, handler.created["decrypt"]["ns-1"].Metadata.GetLabels())

				createdTarget := plan.Actions[0].Targets[0]
				assert.Equal(t, TargetStatusCreate, createdTarget.Status)
				assert.Nil(t, createdTarget.Existing)
				require.NotNil(t, createdTarget.Execution)
				assert.True(t, createdTarget.Execution.Applied)
				assert.Equal(t, "created-action-1", createdTarget.Execution.CreatedTargetID)
				assert.Equal(t, "run-123", createdTarget.Execution.RunID)
				assert.Equal(t, "created-action-1", createdTarget.TargetID())

				existingTarget := plan.Actions[0].Targets[1]
				assert.Equal(t, "standard-action", existingTarget.TargetID())

				migratedTarget := plan.Actions[0].Targets[2]
				assert.Equal(t, "migrated-action", migratedTarget.TargetID())

				assert.Equal(t, "created-action-1", executor.cachedActionTargetID("action-1", namespace1))
				assert.Equal(t, "standard-action", executor.cachedActionTargetID("action-1", namespace2))
				assert.Equal(t, "migrated-action", executor.cachedActionTargetID("action-1", namespace3))
				assert.Empty(t, executor.cachedActionTargetID("action-2", namespace1))
			},
		},
		{
			name: "returns not executable for unresolved target status",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
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
				`action %q target %q is unresolved: %s`,
				"action-1",
				namespace1.GetFqn(),
				"missing target namespace mapping",
			),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.created)
				assert.Empty(t, executor.cachedActionTargetID("action-1", namespace1))
			},
		},
		{
			name: "returns error for missing existing standard target id",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusExistingStandard,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingExistingTarget, `action %q target %q`, "action-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.created)
				assert.Empty(t, executor.cachedActionTargetID("action-1", namespace1))
			},
		},
		{
			name: "returns error for missing already migrated target id",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusAlreadyMigrated,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingMigratedTarget, `action %q target %q`, "action-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.created)
				assert.Empty(t, executor.cachedActionTargetID("action-1", namespace1))
			},
		},
		{
			name: "returns error for missing target namespace",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Status: TargetStatusCreate,
							},
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrTargetNamespaceRequired, `action %q`, "action-1"),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.created)
				assert.Empty(t, executor.cachedActionTargetID("action-1", nil))
			},
		},
		{
			name: "returns error for missing created target id",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
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
			},
			handler: &mockExecutorHandler{
				results: map[string]map[string]*policy.Action{
					"decrypt": {
						"ns-1": {},
					},
				},
			},
			wantErr: wantError(ErrMissingCreatedTargetID, `action %q target %q`, "action-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.created, "decrypt")
				require.NotNil(t, plan.Actions[0].Targets[0].Execution)
				assert.Equal(t, ErrMissingCreatedTargetID.Error(), plan.Actions[0].Targets[0].Execution.Failure)
				assert.Empty(t, executor.cachedActionTargetID("action-1", namespace1))
			},
		},
		{
			name: "returns error for unsupported target status",
			plan: &Plan{
				Scopes: []Scope{ScopeActions},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
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
				`action %q target %q has unsupported status %q`,
				"action-1",
				namespace1.GetFqn(),
				TargetStatus("bogus"),
			),
			assert: func(t *testing.T, err error, executor *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.created)
				assert.Empty(t, executor.cachedActionTargetID("action-1", namespace1))
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
