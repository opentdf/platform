package audit

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
)

func TestGetAuditDataFromContextHappyPath(t *testing.T) {
	ctx := context.Background()
	testRequestID := uuid.New().String()
	testUserAgent := "test-user-agent"
	testRequestIP := "192.168.0.1"
	testActorID := "test-actor-id"

	// Set relevant context keys
	ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, testRequestID)
	ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, testUserAgent)
	ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, testRequestIP)
	ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, testActorID)

	slog.Info(fmt.Sprintf("Test: %v", ctx.Value(sdkAudit.RequestIDContextKey)))

	auditData := GetAuditDataFromContext(ctx)

	if auditData.RequestID.String() != testRequestID {
		t.Fatalf("RequestID did not match: %v", auditData.RequestID)
	}

	if auditData.UserAgent != testUserAgent {
		t.Fatalf("UserAgent did not match: %v", auditData.UserAgent)
	}

	if auditData.RequestIP != testRequestIP {
		t.Fatalf("RequestIP did not match: %v", auditData.RequestIP)
	}

	if auditData.ActorID != testActorID {
		t.Fatalf("ActorID did not match: %v", auditData.ActorID)
	}
}

func TestGetAuditDataFromContextDefaultsPath(t *testing.T) {
	ctx := context.Background()

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
