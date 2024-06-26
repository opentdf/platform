package audit

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateRewrapAuditEventHappyPath(t *testing.T) {
	kasPolicy := KasPolicy{
		UUID: uuid.New(),
		Body: KasPolicyBody{
			DataAttributes: []KasAttribute{
				{URI: "https://example1.com"},
				{URI: "https://example2.com"},
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
			Attrs:       []string{},
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

	if !reflect.DeepEqual(event.Owner, CreateNilOwner()) {
		t.Fatalf("event owner did not match expected: got %+v, want %+v", event.Owner, CreateNilOwner())
	}

	expectedEventActor := auditEventActor{
		ID:         TestActorID,
		Attributes: make([]interface{}, 0),
	}
	if !reflect.DeepEqual(event.Actor, expectedEventActor) {
		t.Fatalf("event actor did not match expected: got %+v, want %+v", event.Actor, expectedEventActor)
	}

	expectedEventMetaData := map[string]string{
		"keyID":         "",
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
		RequestIP: TestRequestIP,
	}
	if !reflect.DeepEqual(event.ClientInfo, expectedClientInfo) {
		t.Fatalf("event client info did not match expected: got %+v, want %+v", event.ClientInfo, expectedClientInfo)
	}

	expectedRequestID, _ := uuid.Parse(TestRequestID)
	if event.RequestID != expectedRequestID {
		t.Fatalf("event request ID did not match expected: got %v, want %v", event.RequestID, expectedRequestID)
	}

	ts, err := time.Parse(time.RFC3339, event.Timestamp)
	if err != nil {
		t.Fatalf("error parsing timestamp: %v", err)
	}

	if time.Since(ts) > time.Second {
		t.Fatalf("event timestamp is not recent: got %v, want less than 1 second", ts)
	}
}
