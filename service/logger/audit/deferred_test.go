package audit

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeferredPolicyCRUD_Success(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditParams := PolicyEventParams{
			ActionType: ActionTypeCreate,
			ObjectType: ObjectTypeAttributeDefinition,
			ObjectID:   "test-id",
		}

		auditEvent := l.PolicyCRUD(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Simulate successful operation
		created := &policy.Attribute{
			Id:   "test-id2",
			Name: "test-attribute",
		}
		auditEvent.Success(ctx, created)
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"create"`, "should contain create action")
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, `"id":"test-id2"`, "should contain object ID")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredPolicyCRUD_Failure(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditParams := PolicyEventParams{
			ActionType: ActionTypeCreate,
			ObjectType: ObjectTypeAttributeDefinition,
			ObjectID:   "test-id",
		}

		auditEvent := l.PolicyCRUD(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Simulate operation failure - don't call Success()
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"create"`, "should contain create action")
	assert.Contains(t, auditJSON, `"result":"error"`, "should contain error result")
	assert.Contains(t, auditJSON, `"id":"test-id"`, "should contain object ID")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredPolicyCRUD_PanicRecovery(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditParams := PolicyEventParams{
			ActionType: ActionTypeUpdate,
			ObjectType: ObjectTypeAttributeDefinition,
			ObjectID:   "test-id",
		}

		auditEvent := l.PolicyCRUD(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Simulate panic during operation
		panic("test panic")
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"update"`, "should contain update action")
	// The interceptor marks panicked events as cancelled
	assert.Contains(t, auditJSON, `"result":"cancel"`, "should contain cancel result")
	assert.Contains(t, auditJSON, `"id":"test-id"`, "should contain object ID")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredPolicyCRUD_ContextCancellation(t *testing.T) {
	l, buf := createTestLogger()
	ctx, cancel := context.WithCancel(createTestContext(t))
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok, "audit transaction missing from context")

	auditParams := PolicyEventParams{
		ActionType: ActionTypeDelete,
		ObjectType: ObjectTypeAttributeDefinition,
		ObjectID:   "test-id",
	}

	func() {
		auditEvent := l.PolicyCRUD(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Cancel the context to simulate network cancellation
		cancel()

		// Don't call Success() - context is cancelled
	}()

	// Manually flush the logs
	tx.logClose(ctx, l.logger, true, nil)

	logEntry, _ := extractLogEntry(t, buf)
	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"delete"`, "should contain delete action")
	assert.Contains(t, auditJSON, `"result":"error"`, "should contain error result")
	assert.Contains(t, auditJSON, `"id":"test-id"`, "should contain object ID")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredRewrap_Success(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		policyUUID := uuid.New()
		auditParams := RewrapAuditEventParams{
			Policy: KasPolicy{
				UUID: policyUUID,
				Body: KasPolicyBody{
					DataAttributes: []KasAttribute{
						{URI: "https://example.com/attr/test"},
					},
				},
			},
			TDFFormat:     "tdf3",
			Algorithm:     "rsa-2048",
			PolicyBinding: "test-binding",
			KeyID:         "test-key-id",
		}

		auditEvent := l.Rewrap(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Simulate successful rewrap
		auditEvent.Success(ctx)
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"rewrap"`, "should contain rewrap action")
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredRewrap_Failure(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		policyUUID := uuid.New()
		auditParams := RewrapAuditEventParams{
			Policy: KasPolicy{
				UUID: policyUUID,
				Body: KasPolicyBody{
					DataAttributes: []KasAttribute{
						{URI: "https://example.com/attr/test"},
					},
				},
			},
			TDFFormat:     "Nano",
			Algorithm:     "aes-256-gcm",
			PolicyBinding: "test-binding",
			KeyID:         "test-key-id",
		}

		auditEvent := l.Rewrap(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Simulate failed rewrap - don't call Success()
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"rewrap"`, "should contain rewrap action")
	assert.Contains(t, auditJSON, `"result":"error"`, "should contain error result")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredPolicyCRUD_MultipleCallsIdempotent(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditParams := PolicyEventParams{
			ActionType: ActionTypeCreate,
			ObjectType: ObjectTypeAttributeDefinition,
			ObjectID:   "test-id",
		}

		auditEvent := l.PolicyCRUD(ctx, auditParams)
		defer auditEvent.Log(ctx)

		created := &policy.Attribute{
			Id:   "test-id",
			Name: "test-attribute",
		}
		auditParams.Original = created

		// Call Success multiple times
		auditEvent.Success(ctx, created)
		auditEvent.Success(ctx, created)
		auditEvent.Success(ctx, created)
	})

	auditJSON := string(logEntry.Audit)
	// Should only have logged once despite multiple Success calls
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
}

func TestDeferredPolicyCRUD_UpdateWithOriginalAndUpdated(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		original := &policy.Attribute{
			Id:   "test-id",
			Name: "original-name",
		}
		updated := &policy.Attribute{
			Id:   "test-id",
			Name: "updated-name",
		}

		auditParams := PolicyEventParams{
			ActionType: ActionTypeUpdate,
			ObjectType: ObjectTypeAttributeDefinition,
			ObjectID:   "test-id",
			Original:   original,
		}

		auditEvent := l.PolicyCRUD(ctx, auditParams)
		defer auditEvent.Log(ctx)

		// Simulate successful update
		auditEvent.Success(ctx, updated)
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"update"`, "should contain update action")
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, `"original"`, "should contain original object")
	assert.Contains(t, auditJSON, `"updated"`, "should contain updated object")
	assert.Contains(t, auditJSON, `"original-name"`, "should contain original name")
	assert.Contains(t, auditJSON, `"updated-name"`, "should contain updated name")
}

func TestDeferredGetDecision_Success(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditEvent := l.Decision(ctx, "test-entity-chain-id", "test-resource-attr-id", []string{"https://example.com/attr/test/value/value1"})
		defer auditEvent.Log(ctx)

		// Simulate successful operation
		entitlements := []EntityChainEntitlement{
			{
				EntityID:                 "entity-1",
				EntityCatagory:           "subject",
				AttributeValueReferences: []string{"https://example.com/attr/test/value/value1"},
			},
		}
		auditEvent.UpdateEntitlements(entitlements)

		entityDecisions := []EntityDecision{
			{
				EntityID:     "entity-1",
				Decision:     "permit",
				Entitlements: []string{"https://example.com/attr/test/value/value1"},
			},
		}
		auditEvent.UpdateEntityDecisions(entityDecisions)

		auditEvent.Success(ctx, GetDecisionResultPermit)
	})

	auditJSON := string(logEntry.Audit)
	// GetDecision events encode decision in action.result as success/failure
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, `"test-entity-chain-id"`, "should contain entity chain ID")
	assert.Contains(t, auditJSON, `entity-1`, "should contain entity ID in metadata")
}

func TestDeferredGetDecision_Failure(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditEvent := l.Decision(ctx, "test-entity-chain-id", "test-resource-attr-id", []string{"https://example.com/attr/test/value/value1"})
		defer auditEvent.Log(ctx)

		// Simulate operation failure - don't call Success()
		// This should default to deny decision (result=failure)
	})

	auditJSON := string(logEntry.Audit)
	// GetDecision events encode deny as action.result = failure
	assert.Contains(t, auditJSON, `"result":"failure"`, "should contain failure result (deny decision)")
	assert.Contains(t, auditJSON, `"test-entity-chain-id"`, "should contain entity chain ID")
}

func TestDeferredGetDecisionV2_Success(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditEvent := l.DecisionV2(ctx, "test-entity-id", "test-action")
		defer auditEvent.Log(ctx)

		// Simulate successful operation with entitlements
		entitlements := make(map[string][]*policy.Action)
		entitlements["https://example.com/attr/test/value/value1"] = []*policy.Action{
			{Name: "test-action"},
		}
		auditEvent.UpdateEntitlements(entitlements)

		// Add obligations
		auditEvent.UpdateObligations([]string{"https://example.com/obligation/test"}, true)

		// Add resource decisions
		resourceDecisions := []map[string]interface{}{
			{
				"passed":                true,
				"obligations_satisfied": true,
				"entitled":              true,
			},
		}
		auditEvent.UpdateResourceDecisions(resourceDecisions)

		auditEvent.Success(ctx, GetDecisionResultPermit)
	})

	auditJSON := string(logEntry.Audit)
	// GetDecisionV2 events encode permit decision as action.result = success
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, `"test-entity-id"`, "should contain entity ID")
	assert.Contains(t, auditJSON, `decisionRequest-test-action`, "should contain action name in object name")
}

func TestDeferredGetDecisionV2_Failure(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditEvent := l.DecisionV2(ctx, "test-entity-id", "test-action")
		defer auditEvent.Log(ctx)

		// Simulate operation failure - don't call Success()
		// This should default to deny decision (result=failure)
	})

	auditJSON := string(logEntry.Audit)
	// GetDecisionV2 events encode deny as action.result = failure
	assert.Contains(t, auditJSON, `"result":"failure"`, "should contain failure result (deny decision)")
	assert.Contains(t, auditJSON, `"test-entity-id"`, "should contain entity ID")
	assert.Contains(t, auditJSON, `decisionRequest-test-action`, "should contain action name in object name")
}

func TestDeferredGetDecisionV2_PanicRecovery(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditEvent := l.DecisionV2(ctx, "test-entity-id", "test-action")
		defer auditEvent.Log(ctx)

		// Simulate panic during operation
		panic("test panic")
	})

	auditJSON := string(logEntry.Audit)
	// Panics are marked as cancel by the interceptor
	assert.Contains(t, auditJSON, `"result":"cancel"`, "should contain cancel result on panic")
	assert.Contains(t, auditJSON, `"test-entity-id"`, "should contain entity ID")
}
