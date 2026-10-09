package audit

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/require"
)

func TestCreateRewrapAuditEventHappyPath(t *testing.T) {
	attrs := []string{
		"https://example1.com",
		"https://example2.com",
	}
	keyID := "r1"

	kasPolicy := KasPolicy{
		UUID: uuid.New(),
		Body: KasPolicyBody{
			DataAttributes: []KasAttribute{
				{URI: attrs[0]},
				{URI: attrs[1]},
			},
			Dissem: []string{"dissem1", "dissem2"},
		},
	}

	sessionKeyType := string(ocrypto.EC256Key)

	params := RewrapAuditEventParams{
		Policy:         kasPolicy,
		Result:         ActionResultSuccess,
		PolicyVerified: true,
		TDFFormat:      TestTDFFormat,
		Algorithm:      TestAlgorithm,
		PolicyBinding:  TestPolicyBinding,
		KeyID:          keyID,
		SessionKeyType: sessionKeyType,
	}

	event, err := CreateRewrapAuditEvent(createTestContext(t), params)
	if err != nil {
		t.Fatalf("error creating rewrap audit event: %v", err)
	}

	expectedEventObject := auditEventObject{
		Type: ObjectTypeKeyObject,
		ID:   kasPolicy.UUID.String(),
		Attributes: eventObjectAttributes{
			EventObjectAttributes: EventObjectAttributes{
				Assertions:  []string{},
				Attrs:       attrs,
				Permissions: []string{},
			},
		},
	}
	if !reflect.DeepEqual(event.Object, expectedEventObject) {
		t.Fatalf("event object did not match expected: got %+v, want %+v", event.Object, expectedEventObject)
	}

	expectedEventAction := eventAction{
		EventObjectAction: EventObjectAction{
			Type:   ActionTypeRewrap,
			Result: ActionResultSuccess,
		},
	}
	if !reflect.DeepEqual(event.Action, expectedEventAction) {
		t.Fatalf("event action did not match expected: got %+v, want %+v", event.Action, expectedEventAction)
	}

	expectedEventActor := auditEventActor{
		EventObjectActor: EventObjectActor{
			ID:         TestActorID,
			Attributes: make([]interface{}, 0),
		},
	}
	if !reflect.DeepEqual(event.Actor, expectedEventActor) {
		t.Fatalf("event actor did not match expected: got %+v, want %+v", event.Actor, expectedEventActor)
	}

	expectedEventMetaData := auditEventMetadata{
		"keyID":            keyID,
		"policyBinding":    TestPolicyBinding,
		"tdfFormat":        TestTDFFormat,
		"algorithm":        TestAlgorithm,
		"sessionKeyType":   sessionKeyType,
		"policy_verified":  true,
		"suspected_tamper": false,
	}
	if !reflect.DeepEqual(event.EventMetaData, expectedEventMetaData) {
		t.Fatalf("event metadata did not match expected: got %+v, want %+v", event.EventMetaData, expectedEventMetaData)
	}

	expectedClientInfo := eventClientInfo{
		EventClientInfo: EventClientInfo{
			Platform:  "kas",
			UserAgent: TestUserAgent,
			RequestIP: TestRequestIP.String(),
		},
	}
	if !reflect.DeepEqual(event.ClientInfo, expectedClientInfo) {
		t.Fatalf("event client info did not match expected: got %+v, want %+v", event.ClientInfo, expectedClientInfo)
	}

	if event.RequestID != TestRequestID {
		t.Fatalf("event request ID did not match expected: got %v, want %v", event.RequestID, TestRequestID)
	}

	validateRecentEventTimestamp(t, event)
}

func TestCreateRewrapAuditEventOmitsUnverifiedPolicyAttributes(t *testing.T) {
	policyID := uuid.New()
	params := RewrapAuditEventParams{
		Policy: KasPolicy{
			UUID: policyID,
			Body: KasPolicyBody{DataAttributes: []KasAttribute{
				{URI: "https://attacker.example/unverified"},
			}},
		},
		PolicyID:        "client-policy-id",
		Result:          ActionResultFailure,
		FailureReason:   "policy_binding_mismatch",
		SuspectedTamper: true,
		PolicyVerified:  false,
		KAOID:           "kao-1",
	}

	event, err := CreateRewrapAuditEvent(createTestContext(t), params)
	require.NoError(t, err)
	require.Equal(t, policyID.String(), event.Object.ID)
	require.Empty(t, event.Object.Attributes.Attrs)
	require.Equal(t, "policy_binding_mismatch", event.EventMetaData["failure_reason"])
	require.Equal(t, true, event.EventMetaData["suspected_tamper"])
	require.Equal(t, false, event.EventMetaData["policy_verified"])
	require.Equal(t, "kao-1", event.EventMetaData["kao_id"])
}
