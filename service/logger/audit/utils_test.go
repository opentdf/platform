package audit

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
)

func TestGetAuditDataFromContextHappyPath(t *testing.T) {
	ctx := t.Context()
	testRequestID := uuid.New()
	testUserAgent := "test-user-agent"
	testRequestIP := net.ParseIP("192.168.0.1")
	testActorID := "test-actor-id"

	// Set relevant context keys
	ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, testRequestID)
	ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, testUserAgent)
	ctx = context.WithValue(ctx, realip.ClientIP{}, testRequestIP)
	ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, testActorID)

	slog.Info("test", slog.Any("test", ctx.Value(sdkAudit.RequestIDContextKey)))

	auditData := GetAuditDataFromContext(ctx)

	if auditData.RequestID.String() != testRequestID.String() {
		t.Fatalf("RequestID did not match: %v", auditData.RequestID)
	}

	if auditData.UserAgent != testUserAgent {
		t.Fatalf("UserAgent did not match: %v", auditData.UserAgent)
	}

	if auditData.RequestIP != testRequestIP.String() {
		t.Fatalf("RequestIP did not match: %v", auditData.RequestIP)
	}

	if auditData.ActorID != testActorID {
		t.Fatalf("ActorID did not match: %v", auditData.ActorID)
	}
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
	testUserAgent := "partial-user-agent"
	testActorID := "partial-actor-id"

	// Set relevant context keys
	ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, testUserAgent)
	ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, testActorID)

	auditData := GetAuditDataFromContext(ctx)

	if auditData.RequestID != uuid.Nil {
		t.Fatalf("RequestID did not match: %v", auditData.RequestID)
	}

	if auditData.UserAgent != testUserAgent {
		t.Fatalf("UserAgent did not match: %v", auditData.UserAgent)
	}

	if auditData.RequestIP != "None" {
		t.Fatalf("RequestIP did not match: %v", auditData.RequestIP)
	}

	if auditData.ActorID != testActorID {
		t.Fatalf("ActorID did not match: %v", auditData.ActorID)
	}
}

func TestGetAuditDataFromContextWrongType(t *testing.T) {
	ctx := t.Context()
	testActorID := 12345

	// Set relevant context keys
	ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, testActorID)

	auditData := GetAuditDataFromContext(ctx)

	if auditData.ActorID != "None" {
		t.Fatalf("ActorID did not match: %v", auditData.ActorID)
	}
}
