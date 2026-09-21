package audit

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
)

func TestCreateGetDecisionEventHappyPathSuccess(t *testing.T) {
	params := GetDecisionEventParams{
		Decision: GetDecisionResultPermit,
		EntityChainEntitlements: []EntityChainEntitlement{
			{
				EntityID:                 "test-entity-id",
				EntityCatagory:           authorization.Entity_CATEGORY_ENVIRONMENT.String(),
				AttributeValueReferences: []string{"test-attribute-value-reference"},
			},
			{
				EntityID:                 "test-entity-id-2",
				EntityCatagory:           authorization.Entity_CATEGORY_SUBJECT.String(),
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

	event, err := CreateGetDecisionEvent(createTestContext(t), params)
	if err != nil {
		t.Fatalf("error creating get decision audit event: %v", err)
	}

	expectedEventObject := auditEventObject{
		Type: ObjectTypeEntityObject,
		ID:   "test-entity-chain-id-test-resource-attribute-id",
		Attributes: eventObjectAttributes{
			EventObjectAttributes: EventObjectAttributes{
				Attrs: []string{"test-fqn"},
			},
		},
	}
	if !reflect.DeepEqual(event.Object, expectedEventObject) {
		t.Fatalf("event object did not match expected: got %+v, want %+v", event.Object, expectedEventObject)
	}

	expectedEventAction := eventAction{
		EventObjectAction: EventObjectAction{
			Type:   ActionTypeRead,
			Result: ActionResultSuccess,
		},
	}
	if !reflect.DeepEqual(event.Action, expectedEventAction) {
		t.Fatalf("event action did not match expected: got %+v, want %+v", event.Action, expectedEventAction)
	}

	expectedEventActor := auditEventActor{
		EventObjectActor: EventObjectActor{
			ID:         "test-entity-chain-id",
			Attributes: buildActorAttributes(params.EntityChainEntitlements),
		},
	}
	if !reflect.DeepEqual(event.Actor, expectedEventActor) {
		t.Fatalf("event actor did not match expected: got %+v, want %+v", event.Actor, expectedEventActor)
	}

	expectedEventMetaData := buildEventMetadata(params.EntityDecisions)
	if !reflect.DeepEqual(event.EventMetaData, expectedEventMetaData) {
		t.Fatalf("event metadata did not match expected: got %+v, want %+v", event.EventMetaData, expectedEventMetaData)
	}

	expectedClientInfo := eventClientInfo{
		EventClientInfo: EventClientInfo{
			Platform:  "authorization",
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

func TestCreateV2GetDecisionEventHappyPathSuccess(t *testing.T) {
	entitlements := subjectmappingbuiltin.AttributeValueFQNsToActions{
		"https://example.com/attr/attr1/value/value1": {{Name: "read"}},
	}
	params := GetDecisionV2EventParams{
		EntityID:                       "test-entity-id",
		ActionName:                     "read",
		Decision:                       GetDecisionResultPermit,
		Entitlements:                   entitlements,
		FulfillableObligationValueFQNs: []string{"https://example.com/obl/obl1/value/value1"},
		ObligationsSatisfied:           true,
		ResourceDecisions:              []string{"test-resource-decision"},
	}

	event, err := CreateV2GetDecisionEvent(createTestContext(t), params)
	if err != nil {
		t.Fatalf("error creating v2 get decision audit event: %v", err)
	}

	expectedEventObject := auditEventObject{
		Type: ObjectTypeEntityObject,
		ID:   "test-entity-id-read",
		Name: "decisionRequest-read",
	}
	if !reflect.DeepEqual(event.Object, expectedEventObject) {
		t.Fatalf("event object did not match expected: got %+v, want %+v", event.Object, expectedEventObject)
	}

	expectedEventAction := eventAction{
		EventObjectAction: EventObjectAction{
			Type:   ActionTypeRead,
			Result: ActionResultSuccess,
		},
	}
	if !reflect.DeepEqual(event.Action, expectedEventAction) {
		t.Fatalf("event action did not match expected: got %+v, want %+v", event.Action, expectedEventAction)
	}

	expectedEventActor := auditEventActor{
		EventObjectActor: EventObjectActor{
			ID: "test-entity-id",
			Attributes: []any{
				struct {
					Entitlements subjectmappingbuiltin.AttributeValueFQNsToActions `json:"entitlements_relevant_to_decision"`
				}{
					Entitlements: entitlements,
				},
			},
		},
	}
	if !reflect.DeepEqual(event.Actor, expectedEventActor) {
		t.Fatalf("event actor did not match expected: got %+v, want %+v", event.Actor, expectedEventActor)
	}

	expectedEventMetaData := auditEventMetadata{
		"resource_decisions":                params.ResourceDecisions,
		"fulfillable_obligation_value_fqns": []string{"https://example.com/obl/obl1/value/value1"},
		"obligations_satisfied":             true,
	}
	if !reflect.DeepEqual(event.EventMetaData, expectedEventMetaData) {
		t.Fatalf("event metadata did not match expected: got %+v, want %+v", event.EventMetaData, expectedEventMetaData)
	}

	expectedClientInfo := eventClientInfo{
		EventClientInfo: EventClientInfo{
			Platform:  "authorization.v2",
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

func TestCreateV2GetDecisionEventDenyWithNilObligations(t *testing.T) {
	params := GetDecisionV2EventParams{
		EntityID:                       "test-entity-id",
		ActionName:                     "read",
		Decision:                       GetDecisionResultDeny,
		FulfillableObligationValueFQNs: nil,
	}

	event, err := CreateV2GetDecisionEvent(createTestContext(t), params)
	if err != nil {
		t.Fatalf("error creating v2 get decision audit event: %v", err)
	}

	if event.Action.Result != ActionResultFailure {
		t.Fatalf("event action result did not match expected: got %v, want %v", event.Action.Result, ActionResultFailure)
	}

	// Nil obligation FQNs are normalized to an empty slice so the emitted audit
	// log carries [] instead of null.
	fulfillable, ok := event.EventMetaData["fulfillable_obligation_value_fqns"].([]string)
	if !ok {
		t.Fatalf("fulfillable obligation value FQNs were not a []string: got %T", event.EventMetaData["fulfillable_obligation_value_fqns"])
	}
	if fulfillable == nil {
		t.Fatal("fulfillable obligation value FQNs were nil, want empty slice")
	}
	if len(fulfillable) != 0 {
		t.Fatalf("fulfillable obligation value FQNs did not match expected: got %v, want []", fulfillable)
	}

	if event.EventMetaData["obligations_satisfied"] != false {
		t.Fatalf("obligations satisfied did not match expected: got %v, want false", event.EventMetaData["obligations_satisfied"])
	}
}

func TestBuildActorAttributes(t *testing.T) {
	entitlements := []EntityChainEntitlement{
		{
			EntityID:                 "test-entity-id",
			EntityCatagory:           authorization.Entity_CATEGORY_ENVIRONMENT.String(),
			AttributeValueReferences: []string{"test-attribute-value-reference"},
		},
		{
			EntityID:                 "test-entity-id-2",
			EntityCatagory:           authorization.Entity_CATEGORY_SUBJECT.String(),
			AttributeValueReferences: []string{"test-attribute-value-reference-2"},
		},
	}

	actual := buildActorAttributes(entitlements)
	expectedMarshal := "[{\"entityId\":\"test-entity-id\",\"entityCategory\":\"CATEGORY_ENVIRONMENT\",\"attributeValueReferences\":[\"test-attribute-value-reference\"]},{\"entityId\":\"test-entity-id-2\",\"entityCategory\":\"CATEGORY_SUBJECT\",\"attributeValueReferences\":[\"test-attribute-value-reference-2\"]}]"
	actualMarshal, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("error marshalling actor attributes: %v", err)
	}

	if string(actualMarshal) != expectedMarshal {
		t.Fatalf("actor attributes did not match expected: got %s, want %s", actualMarshal, expectedMarshal)
	}
}

func TestBuildEventMetadata(t *testing.T) {
	entityDecisions := []EntityDecision{
		{EntityID: "test-entity-id", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement"}},
		{EntityID: "test-entity-id-2", Decision: GetDecisionResultPermit.String(), Entitlements: []string{"test-entitlement-2"}},
	}

	actual := buildEventMetadata(entityDecisions)

	// Verify the structure matches expected
	expected := auditEventMetadata{
		"entities": []map[string]any{
			{
				"id":           "test-entity-id",
				"decision":     "permit",
				"entitlements": []string{"test-entitlement"},
			},
			{
				"id":           "test-entity-id-2",
				"decision":     "permit",
				"entitlements": []string{"test-entitlement-2"},
			},
		},
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("event metadata did not match expected: got %+v, want %+v", actual, expected)
	}
}
