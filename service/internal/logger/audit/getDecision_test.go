package audit

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestCreateGetDecisionEventHappyPathSuccess(t *testing.T) {
	params := GetDecisionEventParams{
		Decision: GetDecisionResultPermit,
		EntityChainEntitlements: []EntityChainEntitlement{
			{
				EntityID:                 "test-entity-id",
				AttributeValueReferences: []string{"test-attribute-value-reference"},
			},
			{
				EntityID:                 "test-entity-id-2",
				AttributeValueReferences: []string{"test-attribute-value-reference-2"},
			},
		},
		EntityChainID: "test-entity-chain-id",
		EntityDecisions: []EntityDecision{
			{EntityID: "test-entity-id", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement"}},
			{EntityID: "test-entity-id-2", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement-2"}},
		},
		ResourceAttributeID: "test-resource-attribute-id",
		FQNs:                []string{"test-fqn"},
	}

	event, err := CreateGetDecisionEvent(createTestContext(), params)

	if err != nil {
		t.Fatalf("error creating get decision audit event: %v", err)
	}

	expectedEventObject := auditEventObject{
		Type: ObjectTypeEntityObject,
		ID:   "test-entity-chain-id-test-resource-attribute-id",
		Attributes: eventObjectAttributes{
			Attrs: []string{"test-fqn"},
		},
	}
	if !reflect.DeepEqual(event.Object, expectedEventObject) {
		t.Fatalf("event object did not match expected: got %+v, want %+v", event.Object, expectedEventObject)
	}

	expectedEventAction := eventAction{
		Type:   ActionTypeRead,
		Result: ActionResultSuccess,
	}
	if !reflect.DeepEqual(event.Action, expectedEventAction) {
		t.Fatalf("event action did not match expected: got %+v, want %+v", event.Action, expectedEventAction)
	}

	if !reflect.DeepEqual(event.Owner, CreateNilOwner()) {
		t.Fatalf("event owner did not match expected: got %+v, want %+v", event.Owner, CreateNilOwner())
	}

	expectedEventActor := auditEventActor{
		ID:         "test-entity-chain-id",
		Attributes: buildActorAttributes(params.EntityChainEntitlements),
	}
	if !reflect.DeepEqual(event.Actor, expectedEventActor) {
		t.Fatalf("event actor did not match expected: got %+v, want %+v", event.Actor, expectedEventActor)
	}

	expectedEventMetaData := buildEventMetadata(params.EntityDecisions)
	if !reflect.DeepEqual(event.EventMetaData, expectedEventMetaData) {
		t.Fatalf("event metadata did not match expected: got %+v, want %+v", event.EventMetaData, expectedEventMetaData)
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

func TestBuildActorAttributes(t *testing.T) {
	entitlements := []EntityChainEntitlement{
		{
			EntityID:                 "test-entity-id",
			AttributeValueReferences: []string{"test-attribute-value-reference"},
		},
		{
			EntityID:                 "test-entity-id-2",
			AttributeValueReferences: []string{"test-attribute-value-reference-2"},
		},
	}

	actual := buildActorAttributes(entitlements)
	expectedMarshal := "[{\"entityId\":\"test-entity-id\",\"attributeValueReferences\":[\"test-attribute-value-reference\"]},{\"entityId\":\"test-entity-id-2\",\"attributeValueReferences\":[\"test-attribute-value-reference-2\"]}]"
	actualMarshal, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("error marshalling actor attributes: %v", err)
	}

	if string(actualMarshal) != expectedMarshal {
		t.Fatalf("actor attributes did not match expected: got %s, want %s", actualMarshal, expectedMarshal)
	}
}

func TestBuildEventMetadata(t *testing.T) {
	expectedMarshal := "{\"entities\":[{\"id\":\"test-entity-id\",\"decision\":\"permit\",\"entitlements\":[\"test-entitlement\"]},{\"id\":\"test-entity-id-2\",\"decision\":\"permit\",\"entitlements\":[\"test-entitlement-2\"]}]}"
	entityDecisions := []EntityDecision{
		{EntityID: "test-entity-id", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement"}},
		{EntityID: "test-entity-id-2", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement-2"}},
	}

	actual := buildEventMetadata(entityDecisions)
	actualMarshal, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("error marshalling event metadata: %v", err)
	}

	if string(actualMarshal) != expectedMarshal {
		t.Fatalf("event metadata did not match expected: got %s, want %s", actualMarshal, expectedMarshal)
	}
}
