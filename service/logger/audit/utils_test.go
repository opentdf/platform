package audit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent(t *testing.T) {
	timestamp := time.Now().Format(time.RFC3339)
	params := EventObjectParams{
		Object: EventObjectInfo{
			Type: ObjectTypeAttributeDefinition,
			ID:   "test-object-id",
			Name: "test-object-name",
			Attributes: EventObjectAttributes{
				Assertions:  []string{"test-assertion"},
				Attrs:       []string{"test-attr"},
				Permissions: []string{"test-permission"},
			},
		},
		Action: EventObjectAction{
			Type:   ActionTypeUpdate,
			Result: ActionResultSuccess,
		},
		Actor: EventObjectActor{
			ID:         TestActorID,
			Attributes: []any{map[string]any{"test-actor-attribute": "test-value"}},
		},
		EventMetaData: EventMetaData{"test-metadata-key": "test-metadata-value"},
		ClientInfo: EventClientInfo{
			UserAgent: TestUserAgent,
			Platform:  "policy",
			RequestIP: TestRequestIP.String(),
		},
		Original:  map[string]any{"test-field": "original-value"},
		Updated:   map[string]any{"test-field": "updated-value"},
		RequestID: TestRequestID,
		Timestamp: timestamp,
	}

	event := NewEvent(params)
	require.NotNil(t, event)

	assert.Equal(t, auditEventObject{
		Type: ObjectTypeAttributeDefinition,
		ID:   "test-object-id",
		Name: "test-object-name",
		Attributes: eventObjectAttributes{
			EventObjectAttributes: params.Object.Attributes,
		},
	}, event.Object)

	assert.Equal(t, eventAction{EventObjectAction: params.Action}, event.Action)
	assert.Equal(t, auditEventActor{EventObjectActor: params.Actor}, event.Actor)
	assert.Equal(t, eventClientInfo{EventClientInfo: params.ClientInfo}, event.ClientInfo)

	assert.Equal(t, params.EventMetaData, event.EventMetaData)
	assert.Equal(t, params.Original, event.Original)
	assert.Equal(t, params.Updated, event.Updated)
	assert.Equal(t, TestRequestID, event.RequestID)
	assert.Equal(t, timestamp, event.Timestamp)
}

func TestNewEventWithZeroValueParams(t *testing.T) {
	event := NewEvent(EventObjectParams{})
	require.NotNil(t, event)

	assert.Equal(t, auditEventObject{}, event.Object)
	assert.Equal(t, eventAction{}, event.Action)
	assert.Equal(t, auditEventActor{}, event.Actor)
	assert.Equal(t, eventClientInfo{}, event.ClientInfo)
	assert.Nil(t, event.EventMetaData)
	assert.Nil(t, event.Original)
	assert.Nil(t, event.Updated)
	assert.Equal(t, uuid.Nil, event.RequestID)
	assert.Empty(t, event.Timestamp)
}

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

func TestGetAuditDataFromContextPrefersVerifiedPrincipal(t *testing.T) {
	token, err := jwt.NewBuilder().Subject("verified-subject").Build()
	require.NoError(t, err)
	ctx := ctxAuth.ContextWithAuthNInfo(ContextWithActorID(t.Context(), "context-actor"), nil, token, "raw-token")

	auditData := GetAuditDataFromContext(ctx)

	assert.Equal(t, "verified-subject", auditData.ActorID)
}
