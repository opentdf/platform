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

		auditEvent := l.DeferPolicyCRUD(ctx, auditParams)
		defer auditEvent.Log()

		// Simulate successful operation
		created := &policy.Attribute{
			Id:   "test-id",
			Name: "test-attribute",
		}
		auditParams.Original = created
		auditEvent.Success(created)
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"create"`, "should contain create action")
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, `"id":"test-id"`, "should contain object ID")
	assert.Contains(t, auditJSON, TestActorID, "should contain actor ID")
}

func TestDeferredPolicyCRUD_Failure(t *testing.T) {
	logEntry, _ := doWithLogger(t, func(ctx context.Context, l *Logger) {
		auditParams := PolicyEventParams{
			ActionType: ActionTypeCreate,
			ObjectType: ObjectTypeAttributeDefinition,
			ObjectID:   "test-id",
		}

		auditEvent := l.DeferPolicyCRUD(ctx, auditParams)
		defer auditEvent.Log()

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

		auditEvent := l.DeferPolicyCRUD(ctx, auditParams)
		defer auditEvent.Log()

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
		auditEvent := l.DeferPolicyCRUD(ctx, auditParams)
		defer auditEvent.Log()

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

		auditEvent := l.DeferRewrap(ctx, auditParams)
		defer auditEvent.Log()

		// Simulate successful rewrap
		auditEvent.Success()
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

		auditEvent := l.DeferRewrap(ctx, auditParams)
		defer auditEvent.Log()

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

		auditEvent := l.DeferPolicyCRUD(ctx, auditParams)
		defer auditEvent.Log()

		created := &policy.Attribute{
			Id:   "test-id",
			Name: "test-attribute",
		}
		auditParams.Original = created

		// Call Success multiple times
		auditEvent.Success(created)
		auditEvent.Success(created)
		auditEvent.Success(created)
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

		auditEvent := l.DeferPolicyCRUD(ctx, auditParams)
		defer auditEvent.Log()

		// Simulate successful update
		auditEvent.Success(updated)
	})

	auditJSON := string(logEntry.Audit)
	assert.Contains(t, auditJSON, `"type":"update"`, "should contain update action")
	assert.Contains(t, auditJSON, `"result":"success"`, "should contain success result")
	assert.Contains(t, auditJSON, `"original"`, "should contain original object")
	assert.Contains(t, auditJSON, `"updated"`, "should contain updated object")
	assert.Contains(t, auditJSON, `"original-name"`, "should contain original name")
	assert.Contains(t, auditJSON, `"updated-name"`, "should contain updated name")
}
