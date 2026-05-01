package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Params
var rewrapAttrs = []string{
	"https://example1.com",
	"https://example2.com",
}

const rewrapAttrsJSON = `["https://example1.com", "https://example2.com"]`

var rewrapParams = RewrapAuditEventParams{
	Policy: KasPolicy{
		UUID: uuid.New(),
		Body: KasPolicyBody{
			DataAttributes: []KasAttribute{
				{URI: rewrapAttrs[0]},
				{URI: rewrapAttrs[1]},
			},
		},
	},
	TDFFormat:     "test-tdf-format",
	Algorithm:     "test-algorithm",
	PolicyBinding: "test-policy-binding",
	KeyID:         "r1",
}

var policyCRUDParams = PolicyEventParams{
	ActionType: ActionTypeUpdate,
	ObjectID:   "test-object-id",
	ObjectType: ObjectTypeKeyObject,
}

func createTestLogger() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer

	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level:       LevelAudit,
		ReplaceAttr: ReplaceAttrAuditLevel,
	})
	logger := slog.New(handler)

	return &Logger{
		logger: logger,
	}, &buf
}

type logEntryStructure struct {
	Time  string          `json:"time"`
	Level string          `json:"level"`
	Msg   string          `json:"msg"`
	Audit json.RawMessage `json:"audit"`
}

func extractLogEntry(t *testing.T, logBuffer *bytes.Buffer) (logEntryStructure, time.Time) {
	loggedString := logBuffer.String()
	if loggedString == "" {
		t.Error("log was empty")
	}

	var entry logEntryStructure
	err := json.Unmarshal([]byte(loggedString), &entry)
	if err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Level != "AUDIT" {
		t.Errorf("Expected level AUDIT, got %s", entry.Level)
	}

	entryTime, err := time.Parse(time.RFC3339, entry.Time)
	if err != nil {
		t.Fatalf("Failed to parse log entry time: %v", err)
	}

	return entry, entryTime
}

func doWithLogger(t *testing.T, contextSetup func(context.Context) context.Context, testFunc func(ctx context.Context, l *Logger)) (ls logEntryStructure, lt time.Time) { //nolint:nonamedreturns // Named returns let the deferred recover path populate the extracted audit log.
	ctx := createTestContext(t)
	if contextSetup != nil {
		ctx = contextSetup(ctx)
	}
	l, buf := createTestLogger()
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok, "audit transaction missing from context")

	defer func() {
		if r := recover(); r != nil {
			if err, okerr := r.(error); okerr {
				tx.logClose(ctx, l, false, err)
			} else {
				tx.logClose(ctx, l, false, nil)
			}
		} else {
			tx.logClose(ctx, l, true, nil)
		}
		ls, lt = extractLogEntry(t, buf)
	}()

	testFunc(ctx, l)

	return ls, lt
}

func createTestJWTForAudit(t *testing.T) (jwt.Token, string) {
	t.Helper()

	token, err := jwt.NewBuilder().
		Subject("jwt-user").
		Claim("realm_access", map[string]any{"roles": []string{"admin", "user"}}).
		Claim("email_verified", true).
		Build()
	require.NoError(t, err)

	rawToken, err := jwt.Sign(token, jwt.WithInsecureNoSignature())
	require.NoError(t, err)

	return token, string(rawToken)
}

func decodeAuditPayload(t *testing.T, payload json.RawMessage) map[string]any {
	t.Helper()

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	return decoded
}

func TestAuditRewrapSuccess(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.RewrapSuccess(ctx, rewrapParams)
	})

	expectedAuditLog := fmt.Sprintf(
		`{
			"object": {
				"type": "key_object",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": [],
					"attrs": %s,
					"permissions": []
				}
			},
			"action": {
			  "type": "rewrap",
				"result": "success"
			},
			"actor": {
			  "id": "%s",
				"attributes": []
			},
			"eventMetaData": {
			  "algorithm": "%s",
				"keyID": "%s",
				"policyBinding": "%s",
				"tdfFormat": "%s"
			},
			"clientInfo": {
			  "userAgent": "%s",
				"platform": "kas",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
	  }
		`,
		rewrapParams.Policy.UUID.String(),
		rewrapAttrsJSON,
		TestActorID,
		rewrapParams.Algorithm,
		rewrapParams.KeyID,
		rewrapParams.PolicyBinding,
		rewrapParams.TDFFormat,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestAuditRewrapFailure(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.RewrapFailure(ctx, rewrapParams)
	})

	expectedAuditLog := fmt.Sprintf(
		`{
			"object": {
				"type": "key_object",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": [],
					"attrs": %s,
					"permissions": []
				}
			},
			"action": {
			  "type": "rewrap",
				"result": "error"
			},
			"actor": {
			  "id": "%s",
				"attributes": []
			},
			"eventMetaData": {
			  "algorithm": "%s",
				"keyID": "%s",
				"policyBinding": "%s",
				"tdfFormat": "%s"
			},
			"clientInfo": {
			  "userAgent": "%s",
				"platform": "kas",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
	  }
		`,
		rewrapParams.Policy.UUID.String(),
		rewrapAttrsJSON,
		TestActorID,
		rewrapParams.Algorithm,
		rewrapParams.KeyID,
		rewrapParams.PolicyBinding,
		rewrapParams.TDFFormat,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestPolicyCRUDSuccess(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.PolicyCRUDSuccess(ctx, policyCRUDParams)
	})

	expectedAuditLog := fmt.Sprintf(
		`{
		  "object": {
			  "type": "%s",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": null,
					"attrs": null,
					"permissions": null
				}
			},
			"action": {
			  "type": "%s",
				"result": "success"
			},
			"actor": {
				"id": "%s",
				"attributes": []
			},
			"eventMetaData": null,
			"clientInfo": {
				"userAgent": "%s",
				"platform": "policy",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
		}`,
		ObjectTypeKeyObject.String(),
		policyCRUDParams.ObjectID,
		ActionTypeUpdate.String(),
		TestActorID,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestPolicyCrudFailure(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.PolicyCRUDFailure(ctx, policyCRUDParams)
	})

	expectedAuditLog := fmt.Sprintf(
		`{
		  "object": {
			  "type": "%s",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": null,
					"attrs": null,
					"permissions": null
}
			},
			"action": {
			  "type": "%s",
				"result": "error"
			},
			"actor": {
				"id": "%s",
				"attributes": []
			},
			"eventMetaData": null,
			"clientInfo": {
				"userAgent": "%s",
				"platform": "policy",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
		}`,
		ObjectTypeKeyObject.String(),
		policyCRUDParams.ObjectID,
		ActionTypeUpdate.String(),
		TestActorID,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestAuditJWTClaimMappingsApplyToPolicyAudit(t *testing.T) {
	token, rawToken := createTestJWTForAudit(t)

	logEntry, _ := doWithLogger(t, func(ctx context.Context) context.Context {
		return ctxAuth.ContextWithAuthNInfo(ctx, nil, token, rawToken)
	}, func(ctx context.Context, l *Logger) {
		require.NoError(t, l.ApplyConfig(Config{
			JWTClaimMappings: []JWTClaimMapping{
				{Claim: "sub", Path: "eventMetaData.requester.sub"},
				{Claim: "realm_access.roles", Path: "eventMetaData.requester.roles"},
				{Claim: "email_verified", Path: "eventMetaData.requester.emailVerified"},
			},
		}))
		l.PolicyCRUDSuccess(ctx, policyCRUDParams)
	})

	payload := decodeAuditPayload(t, logEntry.Audit)
	eventMetaData, ok := payload["eventMetaData"].(map[string]any)
	require.True(t, ok)
	requester, ok := eventMetaData["requester"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "jwt-user", requester["sub"])
	assert.Equal(t, []any{"admin", "user"}, requester["roles"])
	assert.Equal(t, true, requester["emailVerified"])
}

func TestAuditJWTClaimMappingsCanWriteToEntityMetadata(t *testing.T) {
	token, rawToken := createTestJWTForAudit(t)

	logEntry, _ := doWithLogger(t, func(ctx context.Context) context.Context {
		return ctxAuth.ContextWithAuthNInfo(ctx, nil, token, rawToken)
	}, func(ctx context.Context, l *Logger) {
		require.NoError(t, l.ApplyConfig(Config{
			JWTClaimMappings: []JWTClaimMapping{
				{Claim: "sub", Path: "eventMetaData.entityMetadata.sub"},
				{Claim: "realm_access.roles", Path: "eventMetaData.entityMetadata.roles"},
				{Claim: "email_verified", Path: "eventMetaData.entityMetadata.emailVerified"},
			},
		}))
		l.PolicyCRUDSuccess(ctx, policyCRUDParams)
	})

	payload := decodeAuditPayload(t, logEntry.Audit)
	eventMetaData, ok := payload["eventMetaData"].(map[string]any)
	require.True(t, ok)
	entityMetadata, ok := eventMetaData["entityMetadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "jwt-user", entityMetadata["sub"])
	assert.Equal(t, []any{"admin", "user"}, entityMetadata["roles"])
	assert.Equal(t, true, entityMetadata["emailVerified"])
}

func TestAuditJWTClaimMappingsCoverNamedAndUnnamedPaths(t *testing.T) {
	token, rawToken := createTestJWTForAudit(t)

	logEntry, _ := doWithLogger(t, func(ctx context.Context) context.Context {
		return ctxAuth.ContextWithAuthNInfo(ctx, nil, token, rawToken)
	}, func(ctx context.Context, l *Logger) {
		require.NoError(t, l.ApplyConfig(Config{
			JWTClaimMappings: []JWTClaimMapping{
				{Claim: "sub", Path: "object.name"},
				{Claim: "realm_access.roles", Path: "actor.attributes"},
				{Claim: "sub", Path: "original.request.jwt.sub"},
				{Claim: "sub", Path: "banana"},
				{Claim: "email_verified", Path: "kiwi.requester.emailVerified"},
			},
		}))
		l.PolicyCRUDSuccess(ctx, policyCRUDParams)
	})

	payload := decodeAuditPayload(t, logEntry.Audit)

	object, ok := payload["object"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "jwt-user", object["name"])

	actor, ok := payload["actor"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{"admin", "user"}, actor["attributes"])

	original, ok := payload["original"].(map[string]any)
	require.True(t, ok)
	request, ok := original["request"].(map[string]any)
	require.True(t, ok)
	jwt, ok := request["jwt"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "jwt-user", jwt["sub"])

	assert.Equal(t, "jwt-user", payload["banana"])

	kiwi, ok := payload["kiwi"].(map[string]any)
	require.True(t, ok)
	requester, ok := kiwi["requester"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, requester["emailVerified"])
}

func TestAuditJWTClaimMappingsLeaveReservedFieldsUntouched(t *testing.T) {
	token, rawToken := createTestJWTForAudit(t)

	logEntry, _ := doWithLogger(t, func(ctx context.Context) context.Context {
		return ctxAuth.ContextWithAuthNInfo(ctx, nil, token, rawToken)
	}, func(ctx context.Context, l *Logger) {
		require.NoError(t, l.ApplyConfig(Config{
			JWTClaimMappings: []JWTClaimMapping{
				{Claim: "sub", Path: "eventMetaData.requester.sub"},
			},
		}))
		l.PolicyCRUDSuccess(ctx, policyCRUDParams)
	})

	payload := decodeAuditPayload(t, logEntry.Audit)
	assert.Equal(t, TestRequestID.String(), payload["requestID"])

	eventMetaData, ok := payload["eventMetaData"].(map[string]any)
	require.True(t, ok)
	requester, ok := eventMetaData["requester"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "jwt-user", requester["sub"])
}

func TestAuditApplyConfigRejectsReservedPaths(t *testing.T) {
	t.Run("requestID", func(t *testing.T) {
		assertReservedAuditPathRejected(t, "requestID")
	})

	t.Run("clientInfo.userAgent", func(t *testing.T) {
		assertReservedAuditPathRejected(t, "clientInfo.userAgent")
	})

	t.Run("clientInfo.requestIP", func(t *testing.T) {
		assertReservedAuditPathRejected(t, "clientInfo.requestIP")
	})
}

func assertReservedAuditPathRejected(t *testing.T, path string) {
	t.Helper()

	l, _ := createTestLogger()
	err := l.ApplyConfig(Config{
		JWTClaimMappings: []JWTClaimMapping{
			{Claim: "sub", Path: path},
		},
	})

	require.Error(t, err)
	require.ErrorIs(t, err, ErrReservedAuditPath)
	require.ErrorContains(t, err, "jwt_claim_mappings[0].path")
}

func TestDeferredRewrapSuccess(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.RewrapSuccess(ctx, rewrapParams)
	})

	expectedAuditLog := fmt.Sprintf(
		`{
			"object": {
				"type": "key_object",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": [],
					"attrs": %s,
					"permissions": []
				}
			},
			"action": {
			  "type": "rewrap",
				"result": "success"
			},
			"actor": {
			  "id": "%s",
				"attributes": []
			},
			"eventMetaData": {
			  "algorithm": "%s",
				"keyID": "%s",
				"policyBinding": "%s",
				"tdfFormat": "%s"
			},
			"clientInfo": {
			  "userAgent": "%s",
				"platform": "kas",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
	  }
		`,
		rewrapParams.Policy.UUID.String(),
		rewrapAttrsJSON,
		TestActorID,
		rewrapParams.Algorithm,
		rewrapParams.KeyID,
		rewrapParams.PolicyBinding,
		rewrapParams.TDFFormat,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestDeferredRewrapCancelled(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.RewrapSuccess(ctx, rewrapParams)
		panic(errors.New("operation failed"))
	})

	expectedAuditLog := fmt.Sprintf(
		`{
			"object": {
				"type": "key_object",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": [],
					"attrs": %s,
					"permissions": []
				}
			},
			"action": {
			  "type": "rewrap",
				"result": "cancel"
			},
			"actor": {
			  "id": "%s",
				"attributes": []
			},
			"eventMetaData": {
			  "algorithm": "%s",
				"cancellation_error": "%s",
				"keyID": "%s",
				"policyBinding": "%s",
				"tdfFormat": "%s"
			},
			"clientInfo": {
			  "userAgent": "%s",
				"platform": "kas",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
	  }
		`,
		rewrapParams.Policy.UUID.String(),
		rewrapAttrsJSON,
		TestActorID,
		rewrapParams.Algorithm,
		"operation failed",
		rewrapParams.KeyID,
		rewrapParams.PolicyBinding,
		rewrapParams.TDFFormat,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestDeferredPolicyCRUDSuccess(t *testing.T) {
	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.PolicyCRUDSuccess(ctx, policyCRUDParams)
	})

	expectedAuditLog := fmt.Sprintf(
		`{
		  "object": {
			  "type": "%s",
				"id": "%s",
				"name": "",
				"attributes": {
					"assertions": null,
					"attrs": null,
					"permissions": null
				}
			},
			"action": {
			  "type": "%s",
				"result": "success"
			},
			"actor": {
				"id": "%s",
				"attributes": []
			},
			"eventMetaData": null,
			"clientInfo": {
				"userAgent": "%s",
				"platform": "policy",
				"requestIP": "%s"
			},
			"original": null,
			"updated": null,
			"requestID": "%s",
			"timestamp": "%s"
		}`,
		ObjectTypeKeyObject.String(),
		policyCRUDParams.ObjectID,
		ActionTypeUpdate.String(),
		TestActorID,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}

func TestGetDecision(t *testing.T) {
	params := GetDecisionEventParams{
		Decision: GetDecisionResultPermit,
		EntityChainEntitlements: []EntityChainEntitlement{
			{EntityID: "test-entity-id", EntityCatagory: authorization.Entity_CATEGORY_ENVIRONMENT.String(), AttributeValueReferences: []string{"test-attribute-value-reference"}},
		},
		EntityChainID: "test-entity-chain-id",
		EntityDecisions: []EntityDecision{
			{EntityID: "test-entity-id", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement"}},
		},
		ResourceAttributeID: "test-resource-attribute-id",
		FQNs:                []string{"test-fqn"},
	}

	logEntry, logEntryTime := doWithLogger(t, nil, func(ctx context.Context, l *Logger) {
		l.GetDecision(ctx, params)
	})
	expectedAuditLog := fmt.Sprintf(
		`{
				"object": {
					"type": "%s",
					"id": "%s",
					"name": "",
					"attributes": {
						"assertions": null,
						"attrs": %q,
						"permissions": null
					}
				},
				"action": {
					"type": "%s",
					"result": "%s"
				},
				"actor": {
					"id": "%s",
					"attributes": [
						{
							"entityId": "%s",
							"entityCategory": "%s",
							"attributeValueReferences": %q
						}
					]
				},
				"eventMetaData": {
					"entities": [
						{
							"id": "%s",
							"decision": "%s",
							"entitlements": %q
						}
					]
				},
				"clientInfo": {
					"userAgent": "%s",
					"platform": "authorization",
					"requestIP": "%s"
				},
				"original": null,
				"updated": null,
				"requestID": "%s",
				"timestamp": "%s"
		}`,
		ObjectTypeEntityObject.String(),
		fmt.Sprintf("%s-%s", params.EntityChainID, params.ResourceAttributeID),
		params.FQNs,
		ActionTypeRead.String(),
		ActionResultSuccess,
		params.EntityChainID,
		params.EntityChainEntitlements[0].EntityID,
		params.EntityChainEntitlements[0].EntityCatagory,
		params.EntityChainEntitlements[0].AttributeValueReferences,
		params.EntityDecisions[0].EntityID,
		params.EntityDecisions[0].Decision,
		params.EntityDecisions[0].Entitlements,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	// Parse both JSON strings for structural comparison
	var expected, actual map[string]any
	if err := json.Unmarshal([]byte(expectedAuditLog), &expected); err != nil {
		t.Fatalf("Failed to unmarshal expected JSON: %v", err)
	}
	if err := json.Unmarshal(logEntry.Audit, &actual); err != nil {
		t.Fatalf("Failed to unmarshal actual JSON: %v", err)
	}

	loggedMessage := string(logEntry.Audit)
	assert.JSONEq(t, expectedAuditLog, loggedMessage)
}
