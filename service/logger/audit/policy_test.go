package audit

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestCreatePolicyEventHappyPath(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   "test-object-id",
		ObjectType: ObjectTypeKeyObject,
		Original:   nil,
		Updated:    nil,
	}

	event, err := CreatePolicyEvent(createTestContext(), true, params)

	if err != nil {
		t.Fatalf("error creating policy audit event: %v", err)
	}

	expectedEventObject := auditEventObject{
		Type: ObjectTypeKeyObject,
		ID:   "test-object-id",
	}
	if !reflect.DeepEqual(event.Object, expectedEventObject) {
		t.Fatalf("event object did not match expected: got %+v, want %+v", event.Object, expectedEventObject)
	}

	expectedEventAction := eventAction{
		Type:   ActionTypeCreate,
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

	expectedClientInfo := eventClientInfo{
		Platform:  "policy",
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

	validateRecentEventTimestamp(t, event)
}

func TestDiffGenerationUpdateEvents(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeUpdate,
		ObjectID:   "test-object-id",
		ObjectType: ObjectTypeKeyObject,
		Original:   map[string]string{"key": "value", "key2": "value2"},
		Updated:    map[string]string{"key": "updated-value", "key3": "value3"},
	}

	event, err := CreatePolicyEvent(createTestContext(), true, params)

	if err != nil {
		t.Fatalf("error creating policy audit event: %v", err)
	}

	expectedDiff := []DiffEntry{
		{Type: "test", Path: "/key", Value: "value"},
		{Type: "replace", Path: "/key", Value: "updated-value"},
		{Type: "test", Path: "/key2", Value: "value2"},
		{Type: "remove", Path: "/key2", Value: nil},
		{Type: "add", Path: "/key3", Value: "value3"},
	}

	if !reflect.DeepEqual(event.Diff, expectedDiff) {
		t.Fatalf("event diff did not match expected: got %+v, want %+v", event.Diff, expectedDiff)
	}
}
