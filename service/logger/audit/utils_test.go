package audit

import (
	"context"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAuditDataFromContextHappyPath(t *testing.T) {
	ctx := t.Context()

	auditCtx := auditContext{
		data: ContextData{
			RequestID: TestRequestID,
			UserAgent: "test-user-agent",
			RequestIP: net.ParseIP("192.168.0.1").String(),
			ActorID:   "test-actor-id",
		},
	}
	ctx = context.WithValue(ctx, contextKey{}, auditCtx)

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, auditCtx.data.RequestID.String(), auditData.RequestID.String())
	assert.Equal(t, "test-user-agent", auditData.UserAgent)
	assert.Equal(t, net.ParseIP("192.168.0.1").String(), auditData.RequestIP)
	assert.Equal(t, "test-actor-id", auditData.ActorID)
}

func TestGetAuditDataFromContextDefaultsPath(t *testing.T) {
	ctx := t.Context()

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, uuid.Nil, auditData.RequestID)
	assert.Equal(t, defaultNone, auditData.UserAgent)
	assert.Equal(t, defaultNone, auditData.RequestIP)
	assert.Empty(t, auditData.ActorID)
}

func TestGetAuditDataFromContextWithNoKeys(t *testing.T) {
	auditData := GetAuditDataFromContext(t.Context())

	assert.Equal(t, uuid.Nil, auditData.RequestID)
	assert.Equal(t, defaultNone, auditData.UserAgent)
	assert.Equal(t, defaultNone, auditData.RequestIP)
	assert.Empty(t, auditData.ActorID)
}

func TestGetAuditDataFromContextWithPartialKeys(t *testing.T) {
	ctx := t.Context()
	auditCtx := auditContext{
		data: ContextData{
			UserAgent: "partial-user-agent",
			RequestIP: "None",
			ActorID:   "partial-actor-id",
		},
	}
	ctx = context.WithValue(ctx, contextKey{}, auditCtx)

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, uuid.Nil, auditData.RequestID)
	assert.Equal(t, "partial-user-agent", auditData.UserAgent)
	assert.Equal(t, "None", auditData.RequestIP)
	assert.Equal(t, "partial-actor-id", auditData.ActorID)
}

func TestGetAuditDataFromContextPrefersVerifiedPrincipal(t *testing.T) {
	token, err := jwt.NewBuilder().Subject("verified-subject").Build()
	require.NoError(t, err)
	ctx := ctxAuth.ContextWithAuthNInfo(ContextWithActorID(t.Context(), "context-actor"), nil, token, "raw-token")

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, "verified-subject", auditData.ActorID)
}
