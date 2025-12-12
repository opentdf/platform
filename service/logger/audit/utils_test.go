package audit

import (
	"context"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetAuditDataFromContextHappyPath(t *testing.T) {
	ctx := t.Context()

	tx := auditTransaction{
		ContextData: ContextData{
			RequestID: TestRequestID,
			UserAgent: "test-user-agent",
			RequestIP: net.ParseIP("192.168.0.1").String(),
			ActorID:   "test-actor-id",
		},
		events: make([]pendingEvent, 0),
	}
	ctx = context.WithValue(ctx, contextKey{}, &tx)

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, tx.RequestID.String(), auditData.RequestID.String())
	assert.Equal(t, "test-user-agent", auditData.UserAgent)
	assert.Equal(t, net.ParseIP("192.168.0.1").String(), auditData.RequestIP)
	assert.Equal(t, "test-actor-id", auditData.ActorID)
}

func TestGetAuditDataFromContextDefaultsPath(t *testing.T) {
	ctx := t.Context()

	auditData := GetAuditDataFromContext(ctx)

	if auditData.RequestID != uuid.Nil {
		t.Fatalf("RequestID did not match: %v", auditData.RequestID)
	}

	if auditData.UserAgent != defaultNone {
		t.Fatalf("UserAgent did not match: %v", auditData.UserAgent)
	}

	if auditData.RequestIP != defaultNone {
		t.Fatalf("RequestIP did not match: %v", auditData.RequestIP)
	}

	if auditData.ActorID != defaultNone {
		t.Fatalf("ActorID did not match: %v", auditData.ActorID)
	}
}

func TestGetAuditDataFromContextWithNoKeys(t *testing.T) {
	ctx := t.Context()
	auditData := GetAuditDataFromContext(ctx)

	if auditData.RequestID != uuid.Nil {
		t.Fatalf("RequestID did not match: %v", auditData.RequestID)
	}

	if auditData.UserAgent != "None" {
		t.Fatalf("UserAgent did not match: %v", auditData.UserAgent)
	}

	if auditData.RequestIP != "None" {
		t.Fatalf("RequestIP did not match: %v", auditData.RequestIP)
	}

	if auditData.ActorID != "None" {
		t.Fatalf("ActorID did not match: %v", auditData.ActorID)
	}
}

func TestGetAuditDataFromContextWithPartialKeys(t *testing.T) {
	ctx := t.Context()
	tx := auditTransaction{
		ContextData: ContextData{
			UserAgent: "partial-user-agent",
			RequestIP: "None",
			ActorID:   "partial-actor-id",
		},
		events: make([]pendingEvent, 0),
	}
	ctx = context.WithValue(ctx, contextKey{}, &tx)

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, uuid.Nil, auditData.RequestID)
	assert.Equal(t, "partial-user-agent", auditData.UserAgent)
	assert.Equal(t, "None", auditData.RequestIP)
	assert.Equal(t, "partial-actor-id", auditData.ActorID)
}
