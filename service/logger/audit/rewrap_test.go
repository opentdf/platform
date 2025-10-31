package audit

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
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

	params := RewrapAuditEventParams{
		Policy:        kasPolicy,
		IsSuccess:     true,
		TDFFormat:     TestTDFFormat,
		Algorithm:     TestAlgorithm,
		PolicyBinding: TestPolicyBinding,
		KeyID:         keyID,
	}

	event, err := CreateRewrapAuditEvent(createTestContext(), params)
	if err != nil {
		t.Fatalf("error creating rewrap audit event: %v", err)
	}

	expectedEventObject := auditEventObject{
		Type: ObjectTypeKeyObject,
		ID:   kasPolicy.UUID.String(),
		Attributes: eventObjectAttributes{
			Assertions:  []string{},
			Attrs:       attrs,
			Permissions: []string{},
		},
	}
	if !reflect.DeepEqual(event.Object, expectedEventObject) {
		t.Fatalf("event object did not match expected: got %+v, want %+v", event.Object, expectedEventObject)
	}

	expectedEventAction := eventAction{
		Type:   ActionTypeRewrap,
		Result: ActionResultSuccess,
	}
	if !reflect.DeepEqual(event.Action, expectedEventAction) {
		t.Fatalf("event action did not match expected: got %+v, want %+v", event.Action, expectedEventAction)
	}

	expectedEventActor := auditEventActor{
		ID:         TestActorID,
		Attributes: make([]interface{}, 0),
	}
	if !reflect.DeepEqual(event.Actor, expectedEventActor) {
		t.Fatalf("event actor did not match expected: got %+v, want %+v", event.Actor, expectedEventActor)
	}

	expectedEventMetaData := auditEventMetadata{
		"keyID":         keyID,
		"policyBinding": TestPolicyBinding,
		"tdfFormat":     TestTDFFormat,
		"algorithm":     TestAlgorithm,
	}
	if !reflect.DeepEqual(event.EventMetaData, expectedEventMetaData) {
		t.Fatalf("event metadata did not match expected: got %+v, want %+v", event.EventMetaData, expectedEventMetaData)
	}

	expectedClientInfo := eventClientInfo{
		Platform:  "kas",
		UserAgent: TestUserAgent,
		RequestIP: TestRequestIP.String(),
	}
	if !reflect.DeepEqual(event.ClientInfo, expectedClientInfo) {
		t.Fatalf("event client info did not match expected: got %+v, want %+v", event.ClientInfo, expectedClientInfo)
	}

	if event.RequestID != TestRequestID {
		t.Fatalf("event request ID did not match expected: got %v, want %v", event.RequestID, TestRequestID)
	}

	validateRecentEventTimestamp(t, event)
}
