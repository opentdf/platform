package audit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
)

const (
	TestUserAgent = "test-user-agent"
	TestActorID   = "test-actor-id"

	TestTDFFormat     = "nano"
	TestAlgorithm     = "rsa"
	TestPolicyBinding = "test-policy-binding"
)

var TestRequestIP = net.ParseIP("192.168.1.1")

var TestRequestID = uuid.New()

func createTestContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, TestRequestID)
	ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, TestUserAgent)
	ctx = context.WithValue(ctx, realip.ClientIP{}, TestRequestIP)
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
