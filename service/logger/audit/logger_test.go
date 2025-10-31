package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/authorization"
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

func removeWhitespace(s string) string {
	trimmed := strings.ReplaceAll(s, " ", "")
	trimmed = strings.ReplaceAll(trimmed, "\n", "")
	trimmed = strings.ReplaceAll(trimmed, "\t", "")
	return trimmed
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

func TestAuditRewrapSuccess(t *testing.T) {
	l, buf := createTestLogger()

	l.RewrapSuccess(createTestContext(), rewrapParams)

	logEntry, logEntryTime := extractLogEntry(t, buf)

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

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(string(logEntry.Audit))

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

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(string(logEntry.Audit))

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

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(string(logEntry.Audit))

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

	// Remove newlines and spaces from expected
	expectedAuditLog = removeWhitespace(expectedAuditLog)
	loggedMessage := removeWhitespace(string(logEntry.Audit))

	if expectedAuditLog != loggedMessage {
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedAuditLog, loggedMessage)
	}
}

func TestGetDecision(t *testing.T) {
	l, buf := createTestLogger()

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

	l.GetDecision(createTestContext(), params)

	logEntry, logEntryTime := extractLogEntry(t, buf)

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

	if !reflect.DeepEqual(expected, actual) {
		// For better error messages, show the pretty-printed versions
		expectedPretty, _ := json.MarshalIndent(expected, "", "  ")
		actualPretty, _ := json.MarshalIndent(actual, "", "  ")
		t.Errorf("Expected audit log:\n%s\nGot:\n%s", expectedPretty, actualPretty)
	}
}
