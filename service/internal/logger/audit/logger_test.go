package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

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

func removeWhitespace(s string) string {
	trimmed := strings.ReplaceAll(s, " ", "")
	trimmed = strings.ReplaceAll(trimmed, "\n", "")
	trimmed = strings.ReplaceAll(trimmed, "\t", "")
	return trimmed
}

type logEntryStructure struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
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

// Params

var rewrapParams = RewrapAuditEventParams{
	Policy: KasPolicy{
		UUID: uuid.New(),
		Body: KasPolicyBody{
			DataAttributes: []KasAttribute{
				{URI: "https://example1.com"},
				{URI: "https://example2.com"},
			},
		},
	},
	TDFFormat:     "test-tdf-format",
	Algorithm:     "test-algorithm",
	PolicyBinding: "test-policy-binding",
}

var policyCRUDParams = PolicyEventParams{
	ActionType: ActionTypeUpdate,
	ObjectID:   "test-object-id",
	ObjectType: ObjectTypeKeyObject,

	Original: map[string]string{
		"key": "old-value",
	},
	Updated: map[string]string{
		"key": "new-value",
	},
}

func TestAuditRewrapSuccess(t *testing.T) {
	l, buf := createTestLogger()

	l.RewrapSuccess(createTestContext(), rewrapParams)

	logEntry, logEntryTime := extractLogEntry(t, buf)

	expectedAuditLog := fmt.Sprintf(
		`{
			"object": {
				"type": "key_object",
				"id": "%s",
				"attributes": {
				  "assertions": [],
					"attrs": []
				}
			},
			"action": {
			  "type": "rewrap",
				"result": "success"
			},
			"owner": {
			  "id": "%s",
				"orgId": "%s"
			},
			"actor": {
			  "id": "%s",
				"attributes": []
			},
			"eventMetaData": {
			  "algorithm": "%s",
				"keyID": "",
				"policyBinding": "%s",
				"tdfFormat": "%s"
			},
			"clientInfo": {
			  "userAgent": "%s",
				"platform": "kas",
				"requestIp": "%s"
			},
			"requestId": "%s",
			"timestamp": "%s"
	  }
		`,
		rewrapParams.Policy.UUID.String(),
		uuid.Nil.String(),
		uuid.Nil.String(),
		TestActorID,
		rewrapParams.Algorithm,
		rewrapParams.PolicyBinding,
		rewrapParams.TDFFormat,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(logEntry.Msg)

	if expectedAuditLog != loggedMessage {
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedAuditLog, loggedMessage)
	}
}

func TestAuditRewrapFailure(t *testing.T) {
	l, buf := createTestLogger()

	l.RewrapFailure(createTestContext(), rewrapParams)

	logEntry, logEntryTime := extractLogEntry(t, buf)

	expectedAuditLog := fmt.Sprintf(
		`{
			"object": {
				"type": "key_object",
				"id": "%s",
				"attributes": {
				  "assertions": [],
					"attrs": []
				}
			},
			"action": {
			  "type": "rewrap",
				"result": "error"
			},
			"owner": {
			  "id": "%s",
				"orgId": "%s"
			},
			"actor": {
			  "id": "%s",
				"attributes": []
			},
			"eventMetaData": {
			  "algorithm": "%s",
				"keyID": "",
				"policyBinding": "%s",
				"tdfFormat": "%s"
			},
			"clientInfo": {
			  "userAgent": "%s",
				"platform": "kas",
				"requestIp": "%s"
			},
			"requestId": "%s",
			"timestamp": "%s"
	  }
		`,
		rewrapParams.Policy.UUID.String(),
		uuid.Nil.String(),
		uuid.Nil.String(),
		TestActorID,
		rewrapParams.Algorithm,
		rewrapParams.PolicyBinding,
		rewrapParams.TDFFormat,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(logEntry.Msg)

	if expectedAuditLog != loggedMessage {
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedAuditLog, loggedMessage)
	}
}

func TestPolicyCRUDSuccess(t *testing.T) {
	l, buf := createTestLogger()

	l.PolicyCRUDSuccess(createTestContext(), policyCRUDParams)

	logEntry, logEntryTime := extractLogEntry(t, buf)

	expectedAuditLog := fmt.Sprintf(
		`{
		  "object": {
			  "type": "%s",
				"id": "%s",
				"attributes": {
				  "assertions": null,
					"attrs": null
				}
			},
			"action": {
			  "type": "%s",
				"result": "success"
			},
			"owner": {
				"id": "%s",
				"orgId": "%s"
	    },
			"actor": {
				"id": "%s",
				"attributes": []
			},
			"eventMetaData": null,
			"clientInfo": {
				"userAgent": "%s",
				"platform": "policy",
				"requestIp": "%s"
			},
			"diff": [
				{
					"op": "test",
					"path": "/key",
					"value": "old-value"
				},
				{
					"op": "replace",
					"path": "/key",
					"value": "new-value"
				}
			],
			"requestId": "%s",
			"timestamp": "%s"
		}`,
		ObjectTypeKeyObject.String(),
		policyCRUDParams.ObjectID,
		ActionTypeUpdate.String(),
		uuid.Nil.String(),
		uuid.Nil.String(),
		TestActorID,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(logEntry.Msg)

	if expectedAuditLog != loggedMessage {
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedAuditLog, loggedMessage)
	}
}

func TestPolicyCrudFailure(t *testing.T) {
	l, buf := createTestLogger()

	l.PolicyCRUDFailure(createTestContext(), policyCRUDParams)

	logEntry, logEntryTime := extractLogEntry(t, buf)

	expectedAuditLog := fmt.Sprintf(
		`{
		  "object": {
			  "type": "%s",
				"id": "%s",
				"attributes": {
				  "assertions": null,
					"attrs": null
				}
			},
			"action": {
			  "type": "%s",
				"result": "error"
			},
			"owner": {
				"id": "%s",
				"orgId": "%s"
	    },
			"actor": {
				"id": "%s",
				"attributes": []
			},
			"eventMetaData": null,
			"clientInfo": {
				"userAgent": "%s",
				"platform": "policy",
				"requestIp": "%s"
			},
			"requestId": "%s",
			"timestamp": "%s"
		}`,
		ObjectTypeKeyObject.String(),
		policyCRUDParams.ObjectID,
		ActionTypeUpdate.String(),
		uuid.Nil.String(),
		uuid.Nil.String(),
		TestActorID,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(logEntry.Msg)

	if expectedAuditLog != loggedMessage {
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedAuditLog, loggedMessage)
	}
}

func TestGetDecision(t *testing.T) {
	l, buf := createTestLogger()

	params := GetDecisionEventParams{
		Decision: GetDecisionResultPermit,
		EntityChainEntitlements: []EntityChainEntitlement{
			{EntityID: "test-entity-id", AttributeValueReferences: []string{"test-attribute-value-reference"}},
		},
		EntityChainID: "test-entity-chain-id",
		EntityDecisions: []EntityDecision{
			{EntityID: "test-entity-id", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement"}},
		},
		ResourceAttributeID: "test-resource-attribute-id",
		FQNs:                []string{"test-fqn"},
	}

	l.GetDecision(createTestContext(), params)

	logEntry, logEntryTime := extractLogEntry(t, buf)

	expectedAuditLog := fmt.Sprintf(
		`{
				"object": {
					"type": "%s",
					"id": "%s",
					"attributes": {
						"assertions": null,
						"attrs": %q
					}
				},
				"action": {
					"type": "%s",
					"result": "%s"
				},
				"owner": {
					"id": "%s",
					"orgId": "%s"
				},
				"actor": {
					"id": "%s",
					"attributes": [
						{
							"entityId": "%s",
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
					"requestIp": "%s"
				},
				"requestId": "%s",
				"timestamp": "%s"
		}`,
		ObjectTypeEntityObject.String(),
		fmt.Sprintf("%s-%s", params.EntityChainID, params.ResourceAttributeID),
		params.FQNs,
		ActionTypeRead.String(),
		ActionResultSuccess,
		uuid.Nil.String(),
		uuid.Nil.String(),
		params.EntityChainID,
		params.EntityChainEntitlements[0].EntityID,
		params.EntityChainEntitlements[0].AttributeValueReferences,
		params.EntityDecisions[0].EntityID,
		params.EntityDecisions[0].Decision,
		params.EntityDecisions[0].Entitlements,
		TestUserAgent,
		TestRequestIP,
		TestRequestID,
		logEntryTime.Format(time.RFC3339),
	)

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(logEntry.Msg)

	if expectedAuditLog != loggedMessage {
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedAuditLog, loggedMessage)
	}
}
