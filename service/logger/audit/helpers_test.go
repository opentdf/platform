package audit

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"

	sdkAudit "github.com/opentdf/platform/sdk/audit"
)

const (
	TestUserAgent     = "test-user-agent"
	TestActorID       = "test-actor-id"
	TestRequestIP     = "192.168.1.1"
	TestTDFFormat     = "nano"
	TestAlgorithm     = "rsa"
	TestPolicyBinding = "test-policy-binding"
)

var TestRequestID = uuid.New()

func createTestContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, TestRequestID)
	ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, TestUserAgent)
	ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, TestRequestIP)
	ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, TestActorID)
	return ctx
}

func validateRecentEventTimestamp(t *testing.T, event *EventObject) {
	if event.Timestamp == "" {
		t.Fatalf("event timestamp is empty")
	}

	eventTime, err := time.Parse(time.RFC3339, event.Timestamp)
	if err != nil {
		t.Fatalf("error parsing timestamp: %v", err)
	}

	if time.Since(eventTime) > time.Second {
		t.Fatalf("event timestamp is not recent: got %v, want less than 1 second", eventTime)
	}
}
