package audit

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var originalPolicyObject = &TestPolicyObject{
	Id:         "1234",
	Active:     &wrapperspb.BoolValue{Value: true},
	Version:    TestPolicyObjectVersionEnum_TEST_POLICY_OBJECT_VERSION_ENUM_OLD,
	Tags:       []string{"tag1", "tag2"},
	PolicyUser: &TestPolicyObject_Username{Username: "test-username"},
	Metadata: &common.Metadata{
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
		Labels:    map[string]string{"key": "value"},
	},
}

func runWithUpdatedTest(t *testing.T, params PolicyEventParams, expectedAuditUpdatedObject map[string]interface{}) {
	event, err := CreatePolicyEvent(createTestContext(), true, params)
	require.Nil(t, err)
	require.True(t,
		reflect.DeepEqual(event.Updated, expectedAuditUpdatedObject),
		"event.Updated did not match expected: got %+v expected %+v", event.Updated, expectedAuditUpdatedObject,
	)
}

func Test_CreatePolicyEvent_HappyPath(t *testing.T) {
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

	require.Nil(t, event.Original)
	require.Nil(t, event.Updated)
}

func Test_CreatePolicyEvent_WithOriginal(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   originalPolicyObject.Id,
		ObjectType: ObjectTypeKeyObject,
		Original:   originalPolicyObject,
	}

	event, err := CreatePolicyEvent(createTestContext(), true, params)

	if err != nil {
		t.Fatalf("error creating policy audit event: %v", err)
	}

	require.NotNil(t, event.Original)
	require.Nil(t, event.Updated)

	expected := map[string]interface{}{
		"id":      "1234",
		"active":  true,
		"version": "TEST_POLICY_OBJECT_VERSION_ENUM_OLD",
		// []interface{} must be used because json.Unmarshal returns []interface{} for JSON arrays
		"tags":     []interface{}{"tag1", "tag2"},
		"username": "test-username",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"key": "value"},
		},
	}
	require.True(t, reflect.DeepEqual(event.Original, expected),
		"event original did not match expected: got %+v expected %+v", event.Original, expected)
}

func Test_CreatePolicyEvent_WithUpdated_BoolPropertyModified(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   originalPolicyObject.Id,
		ObjectType: ObjectTypeKeyObject,
		Original:   originalPolicyObject,
		Updated: &TestPolicyObject{
			Active: &wrapperspb.BoolValue{Value: false},
		},
	}

	expected := map[string]interface{}{
		"id":      "1234",
		"active":  false,
		"version": "TEST_POLICY_OBJECT_VERSION_ENUM_OLD",
		// []interface{} must be used because json.Unmarshal returns []interface{} for JSON arrays
		"tags":     []interface{}{"tag1", "tag2"},
		"username": "test-username",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"key": "value"},
		},
	}

	runWithUpdatedTest(t, params, expected)
}

func Test_CreatePolicyEvent_WithUpdated_EnumPropertyModified(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   originalPolicyObject.Id,
		ObjectType: ObjectTypeKeyObject,
		Original:   originalPolicyObject,
		Updated: &TestPolicyObject{
			Version: TestPolicyObjectVersionEnum_TEST_POLICY_OBJECT_VERSION_ENUM_NEW,
		},
	}

	expected := map[string]interface{}{
		"id":      "1234",
		"active":  true,
		"version": "TEST_POLICY_OBJECT_VERSION_ENUM_NEW",
		// []interface{} must be used because json.Unmarshal returns []interface{} for JSON arrays
		"tags":     []interface{}{"tag1", "tag2"},
		"username": "test-username",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"key": "value"},
		},
	}

	runWithUpdatedTest(t, params, expected)
}

func Test_CreatePolicyEvent_WithUpdated_ArrayPropertyModified(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   originalPolicyObject.Id,
		ObjectType: ObjectTypeKeyObject,
		Original:   originalPolicyObject,
		Updated: &TestPolicyObject{
			Tags: []string{"single-tag"},
		},
	}

	expected := map[string]interface{}{
		"id":      "1234",
		"active":  true,
		"version": "TEST_POLICY_OBJECT_VERSION_ENUM_OLD",
		// []interface{} must be used because json.Unmarshal returns []interface{} for JSON arrays
		"tags":     []interface{}{"single-tag"},
		"username": "test-username",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"key": "value"},
		},
	}

	runWithUpdatedTest(t, params, expected)
}

func Test_CreatePolicyEvent_WithUpdated_OneOfPropertyModified(t *testing.T) {
	t.Skip("Revisit once audit strategy can handle auditing oneOf properties correctly")

	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   originalPolicyObject.Id,
		ObjectType: ObjectTypeKeyObject,
		Original:   originalPolicyObject,
		Updated: &TestPolicyObject{
			PolicyUser: &TestPolicyObject_User{User: &User{Id: "1234", Name: "test-user"}},
		},
	}

	expected := map[string]interface{}{
		"id":      "1234",
		"active":  true,
		"version": "TEST_POLICY_OBJECT_VERSION_ENUM_OLD",
		// []interface{} must be used because json.Unmarshal returns []interface{} for JSON arrays
		"tags": []interface{}{"tag1", "tag2"},
		"user": map[string]interface{}{
			"id":   "1234",
			"name": "test-user",
		},
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"key": "value"},
		},
	}

	runWithUpdatedTest(t, params, expected)
}

func Test_CreatePolicyEvent_WithUpdated_MetadataPropertyModified(t *testing.T) {
	params := PolicyEventParams{
		ActionType: ActionTypeCreate,
		ObjectID:   originalPolicyObject.Id,
		ObjectType: ObjectTypeKeyObject,
		Original:   originalPolicyObject,
		Updated: &TestPolicyObject{
			Metadata: &common.Metadata{
				Labels: map[string]string{
					"newKey":  "newMe",
					"another": "one",
				},
			},
		},
	}

	expected := map[string]interface{}{
		"id":      "1234",
		"active":  true,
		"version": "TEST_POLICY_OBJECT_VERSION_ENUM_OLD",
		// []interface{} must be used because json.Unmarshal returns []interface{} for JSON arrays
		"tags":     []interface{}{"tag1", "tag2"},
		"username": "test-username",
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"newKey": "newMe", "another": "one"},
		},
	}

	runWithUpdatedTest(t, params, expected)
}
