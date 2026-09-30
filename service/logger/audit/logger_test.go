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

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuiltInHelpersReturnProcessorErrors(t *testing.T) {
	processorErr := errors.New("audit destination unavailable")
	for _, tt := range []struct {
		name   string
		verb   Verb
		record func(context.Context, *Logger) error
	}{
		{"rewrap success", VerbRewrap, func(ctx context.Context, l *Logger) error { return l.RewrapSuccess(ctx, rewrapParams) }},
		{"rewrap failure", VerbRewrap, func(ctx context.Context, l *Logger) error { return l.RewrapFailure(ctx, rewrapParams) }},
		{"policy success", VerbPolicyCRUD, func(ctx context.Context, l *Logger) error { return l.PolicyCRUDSuccess(ctx, policyCRUDParams) }},
		{"policy failure", VerbPolicyCRUD, func(ctx context.Context, l *Logger) error { return l.PolicyCRUDFailure(ctx, policyCRUDParams) }},
		{"decision", VerbDecision, func(ctx context.Context, l *Logger) error { return l.GetDecision(ctx, GetDecisionEventParams{}) }},
		{"decision v2", VerbDecision, func(ctx context.Context, l *Logger) error { return l.GetDecisionV2(ctx, GetDecisionV2EventParams{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, output := createTestLogger()
			calls := 0
			l.processor = ProcessorFunc(func(_ context.Context, event Event) error {
				calls++
				require.Equal(t, tt.verb, event.Verb)
				return processorErr
			})
			err := tt.record(t.Context(), l)
			require.ErrorIs(t, err, processorErr)
			require.ErrorIs(t, err, ErrProcessing)
			require.Equal(t, 1, calls)
			require.Empty(t, output.String(), "no implicit fallback or duplicate delivery")
		})
	}
}

func TestPolicyHelperReturnsConstructionError(t *testing.T) {
	l, output := createTestLogger()
	params := policyCRUDParams
	params.Original = structpb.NewStringValue(string([]byte{0xff}))
	l.processor = ProcessorFunc(func(context.Context, Event) error {
		t.Fatal("invalid event must not reach processor")
		return nil
	})
	require.Error(t, l.PolicyCRUDSuccess(t.Context(), params))
	require.Empty(t, output.String())
}

func TestRewrapFailureOverridesSuccessfulAccess(t *testing.T) {
	l, output := createTestLogger()
	params := rewrapParams
	params.IsSuccess = true
	require.NoError(t, l.RewrapFailure(t.Context(), params))
	entry, _ := extractLogEntry(t, output)
	payload := decodeAuditPayload(t, entry.Audit)
	require.Equal(t, ActionResultError.String(), requireMap(t, payload["action"])["result"])
}

func TestBuiltInRecordingPreservesCanceledProducerContext(t *testing.T) {
	type ownerKey struct{}
	var processed bool
	l := CreateAuditLogger(*slog.New(slog.DiscardHandler),
		WithRecordTimeout(time.Second),
		WithProcessor(ProcessorFunc(func(ctx context.Context, event Event) error {
			processed = true
			require.NoError(t, ctx.Err())
			require.Equal(t, "resource-owner", ctx.Value(ownerKey{}))
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.Positive(t, time.Until(deadline))
			require.LessOrEqual(t, time.Until(deadline), time.Second)
			require.Equal(t, "producer", event.Actor.ID)
			return nil
		})))
	next := ContextServerInterceptor()(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = ContextWithActorID(context.WithValue(ctx, ownerKey{}, "resource-owner"), "producer")
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
		require.True(t, processed, "recording must finish before the producer returns")
		return connect.NewResponse(&struct{}{}), nil
	})
	_, err := next(t.Context(), connect.NewRequest(&struct{}{}))
	require.NoError(t, err)
}

func TestCompletedEventSurvivesLaterRPCFailure(t *testing.T) {
	for _, panicLater := range []bool{false, true} {
		name := "error"
		if panicLater {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			l, output := createTestLogger()
			laterErr := errors.New("later operation failed")
			next := ContextServerInterceptor()(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				require.NoError(t, l.RewrapSuccess(ctx, rewrapParams))
				require.NotEmpty(t, output.String(), "event must be emitted immediately")
				if panicLater {
					panic(laterErr)
				}
				return nil, laterErr
			})
			if panicLater {
				require.PanicsWithValue(t, laterErr, func() {
					_, _ = next(t.Context(), connect.NewRequest(&struct{}{}))
				})
			} else {
				_, err := next(t.Context(), connect.NewRequest(&struct{}{}))
				require.ErrorIs(t, err, laterErr)
			}
			entry, _ := extractLogEntry(t, output)
			payload := decodeAuditPayload(t, entry.Audit)
			require.Equal(t, ActionResultSuccess.String(), requireMap(t, payload["action"])["result"])
			require.NotContains(t, requireMap(t, payload["eventMetaData"]), "cancellation_error")
		})
	}
}

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

func doWithLogger(t *testing.T, contextSetup func(context.Context) context.Context, testFunc func(ctx context.Context, l *Logger)) (logEntryStructure, time.Time) {
	t.Helper()
	ctx := createTestContext(t)
	if contextSetup != nil {
		ctx = contextSetup(ctx)
	}
	l, buf := createTestLogger()
	testFunc(ctx, l)
	return extractLogEntry(t, buf)
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
		require.NoError(t, l.RewrapSuccess(ctx, rewrapParams))
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
		require.NoError(t, l.RewrapFailure(ctx, rewrapParams))
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
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
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
		require.NoError(t, l.PolicyCRUDFailure(ctx, policyCRUDParams))
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
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
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
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
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
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
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
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
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

func TestAuditApplyConfigClonesMappings(t *testing.T) {
	l, _ := createTestLogger()
	cfg := Config{
		JWTClaimMappings: []JWTClaimMapping{
			{Claim: "sub", Path: "eventMetaData.requester.sub"},
		},
	}

	require.NoError(t, l.ApplyConfig(cfg))

	cfg.JWTClaimMappings[0].Path = "eventMetaData.requester.changed"

	require.Equal(t, "eventMetaData.requester.sub", l.config.JWTClaimMappings[0].Path)
}

func TestAuditLoggerWithClonesMappings(t *testing.T) {
	l, _ := createTestLogger()
	require.NoError(t, l.ApplyConfig(Config{
		JWTClaimMappings: []JWTClaimMapping{
			{Claim: "sub", Path: "eventMetaData.requester.sub"},
		},
	}))

	child := l.With("namespace", "policy")
	l.config.JWTClaimMappings[0].Path = "eventMetaData.requester.changed"

	require.Equal(t, "eventMetaData.requester.sub", child.config.JWTClaimMappings[0].Path)
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
		require.NoError(t, l.GetDecision(ctx, params))
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
