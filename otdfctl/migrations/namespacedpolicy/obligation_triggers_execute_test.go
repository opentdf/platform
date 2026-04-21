package namespacedpolicy

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteObligationTriggers(t *testing.T) {
	t.Parallel()

	namespace1 := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	namespace2 := &policy.Namespace{Id: "ns-2", Fqn: "https://example.net"}
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
			name: "handles created and already migrated obligation trigger targets",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeObligationTriggers},
				Actions: []*ActionPlan{
					{
						Source: &policy.Action{Id: "action-1", Name: "decrypt"},
						Targets: []*ActionTargetPlan{
							{
								Namespace: namespace1,
								Status:    TargetStatusCreate,
							},
							{
								Namespace:  namespace2,
								Status:     TargetStatusExistingStandard,
								ExistingID: "existing-standard-action",
							},
						},
					},
				},
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{
							Id:     "trigger-1",
							Action: &policy.Action{Id: "action-1"},
							AttributeValue: &policy.Value{
								Id:  "attribute-value-1",
								Fqn: "https://example.com/attr/department/value/eng",
							},
							ObligationValue: &policy.ObligationValue{
								Id:  "obligation-value-1",
								Fqn: "https://example.com/obligation/log/value/default",
							},
							Context: []*policy.RequestContext{
								{Pep: &policy.PolicyEnforcementPoint{ClientId: "client-a"}},
							},
							Metadata: &common.Metadata{
								Labels: map[string]string{
									"owner": "policy-team",
									"env":   "dev",
								},
							},
						},
						Target: &ObligationTriggerTargetPlan{
							Namespace:      namespace1,
							Status:         TargetStatusCreate,
							ActionSourceID: "action-1",
						},
					},
					{
						Source: &policy.ObligationTrigger{
							Id:     "trigger-2",
							Action: &policy.Action{Id: "action-1"},
						},
						Target: &ObligationTriggerTargetPlan{
							Namespace:      namespace2,
							Status:         TargetStatusAlreadyMigrated,
							ExistingID:     "migrated-trigger-2",
							ActionSourceID: "action-1",
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
				obligationTriggerResult: map[string]map[string]*policy.ObligationTrigger{
					"trigger-1": {
						"created-action-1": {Id: "created-trigger-1"},
					},
				},
			},
			runID: "run-789",
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.NoError(t, err)
				require.Contains(t, handler.createdObligationTriggers, "trigger-1")
				require.Contains(t, handler.createdObligationTriggers["trigger-1"], "created-action-1")

				createdCall := handler.createdObligationTriggers["trigger-1"]["created-action-1"]
				assert.Equal(t, "attribute-value-1", createdCall.AttributeValue)
				assert.Equal(t, "created-action-1", createdCall.Action)
				assert.Equal(t, "obligation-value-1", createdCall.ObligationValue)
				assert.Equal(t, "client-a", createdCall.ClientID)
				assert.Equal(t, map[string]string{
					"owner":                    "policy-team",
					"env":                      "dev",
					migrationLabelMigratedFrom: "trigger-1",
					migrationLabelRun:          "run-789",
				}, createdCall.Metadata.GetLabels())

				createdTarget := plan.ObligationTriggers[0].Target
				require.NotNil(t, createdTarget.Execution)
				assert.True(t, createdTarget.Execution.Applied)
				assert.Equal(t, "created-trigger-1", createdTarget.Execution.CreatedTargetID)
				assert.Equal(t, "run-789", createdTarget.Execution.RunID)
				assert.Equal(t, "created-trigger-1", createdTarget.TargetID())

				migratedTarget := plan.ObligationTriggers[1].Target
				assert.Equal(t, "migrated-trigger-2", migratedTarget.TargetID())
				assert.Nil(t, migratedTarget.Execution)
			},
		},
		{
			name: "returns not executable for unresolved target status",
			plan: &Plan{
				Scopes: []Scope{ScopeObligationTriggers},
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{Id: "trigger-1"},
						Target: &ObligationTriggerTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusUnresolved,
							Reason:    "missing target namespace mapping",
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(
				ErrPlanNotExecutable,
				`obligation trigger %q target %q is unresolved: %s`,
				"trigger-1",
				namespace1.GetFqn(),
				"missing target namespace mapping",
			),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdObligationTriggers)
			},
		},
		{
			name: "returns error when migrated action target is unavailable",
			plan: &Plan{
				Scopes: []Scope{ScopeObligationTriggers},
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{
							Id:              "trigger-1",
							Action:          &policy.Action{Id: "action-1"},
							AttributeValue:  &policy.Value{Id: "attribute-value-1"},
							ObligationValue: &policy.ObligationValue{Id: "obligation-value-1"},
						},
						Target: &ObligationTriggerTargetPlan{
							Namespace:      namespace1,
							Status:         TargetStatusCreate,
							ActionSourceID: "action-1",
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingMigratedTarget, `obligation trigger %q action %q target %q`, "trigger-1", "action-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdObligationTriggers)
				assert.Nil(t, plan.ObligationTriggers[0].Target.Execution)
			},
		},
		{
			name: "returns error for missing already migrated trigger id",
			plan: &Plan{
				Scopes: []Scope{ScopeObligationTriggers},
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{Id: "trigger-1"},
						Target: &ObligationTriggerTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatusAlreadyMigrated,
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(ErrMissingMigratedTarget, `obligation trigger %q target %q`, "trigger-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdObligationTriggers)
			},
		},
		{
			name: "returns error for missing created target id",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeObligationTriggers},
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
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{
							Id:              "trigger-1",
							Action:          &policy.Action{Id: "action-1"},
							AttributeValue:  &policy.Value{Id: "attribute-value-1"},
							ObligationValue: &policy.ObligationValue{Id: "obligation-value-1"},
						},
						Target: &ObligationTriggerTargetPlan{
							Namespace:      namespace1,
							Status:         TargetStatusCreate,
							ActionSourceID: "action-1",
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
				obligationTriggerResult: map[string]map[string]*policy.ObligationTrigger{
					"trigger-1": {
						"created-action-1": {},
					},
				},
			},
			wantErr: wantError(ErrMissingCreatedTargetID, `obligation trigger %q target %q`, "trigger-1", namespace1.GetFqn()),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdObligationTriggers, "trigger-1")
				require.NotNil(t, plan.ObligationTriggers[0].Target.Execution)
				assert.Equal(t, ErrMissingCreatedTargetID.Error(), plan.ObligationTriggers[0].Target.Execution.Failure)
			},
		},
		{
			name: "records create failure from handler",
			plan: &Plan{
				Scopes: []Scope{ScopeActions, ScopeObligationTriggers},
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
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{
							Id:              "trigger-1",
							Action:          &policy.Action{Id: "action-1"},
							AttributeValue:  &policy.Value{Id: "attribute-value-1"},
							ObligationValue: &policy.ObligationValue{Id: "obligation-value-1"},
						},
						Target: &ObligationTriggerTargetPlan{
							Namespace:      namespace1,
							Status:         TargetStatusCreate,
							ActionSourceID: "action-1",
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
				obligationTriggerErrs: map[string]map[string]error{
					"trigger-1": {
						"created-action-1": errBoom,
					},
				},
			},
			wantErr: &expectedError{
				is:      errBoom,
				message: `create obligation trigger "trigger-1" in namespace "https://example.com": boom`,
			},
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, plan *Plan) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, handler.createdObligationTriggers, "trigger-1")
				require.NotNil(t, plan.ObligationTriggers[0].Target.Execution)
				assert.Equal(t, "boom", plan.ObligationTriggers[0].Target.Execution.Failure)
			},
		},
		{
			name: "returns error for unsupported target status",
			plan: &Plan{
				Scopes: []Scope{ScopeObligationTriggers},
				ObligationTriggers: []*ObligationTriggerPlan{
					{
						Source: &policy.ObligationTrigger{Id: "trigger-1"},
						Target: &ObligationTriggerTargetPlan{
							Namespace: namespace1,
							Status:    TargetStatus("bogus"),
						},
					},
				},
			},
			handler: &mockExecutorHandler{},
			wantErr: wantError(
				ErrUnsupportedStatus,
				`obligation trigger %q target %q has unsupported status %q`,
				"trigger-1",
				namespace1.GetFqn(),
				TargetStatus("bogus"),
			),
			assert: func(t *testing.T, err error, _ *Executor, handler *mockExecutorHandler, _ *Plan) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, handler.createdObligationTriggers)
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
