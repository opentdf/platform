package audit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestUserAgent = "test-user-agent"
	TestActorID   = "test-actor-id"

	TestTDFFormat     = "ztdf"
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
	require.NoError(t, err, "error parsing timestamp [%v]", event.Timestamp)
	assert.Greater(t, time.Second, time.Since(eventTime), "event timestamp is not recent: got %v, want less than 1 second", eventTime)
}
