package audit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
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

func createTestContext(t *testing.T) context.Context {
	ctx := t.Context()

	tx := auditTransaction{
		ContextData: ContextData{
			RequestID: TestRequestID,
			UserAgent: TestUserAgent,
			RequestIP: TestRequestIP.String(),
			ActorID:   TestActorID,
		},
		events: make([]pendingEvent, 0),
	}
	ctx = context.WithValue(ctx, contextKey{}, &tx)

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
