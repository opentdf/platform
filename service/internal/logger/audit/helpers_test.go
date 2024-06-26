package audit

import (
	"context"

	sdkAudit "github.com/opentdf/platform/sdk/audit"
)

const (
	TestRequestID     = "60d77895-b330-42da-92d2-5a9aa773fa1b"
	TestUserAgent     = "test-user-agent"
	TestActorID       = "test-actor-id"
	TestRequestIP     = "192.168.1.1"
	TestTDFFormat     = "nano"
	TestAlgorithm     = "rsa"
	TestPolicyBinding = "test-policy-binding"
)

func createTestContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, TestRequestID)
	ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, TestUserAgent)
	ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, TestRequestIP)
	ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, TestActorID)
	return ctx
}
