package cukes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

type AuthorizationServiceStepDefinitions struct{}

const (
	decisionResponse = "decisionResponse"
)

func ConvertInterfaceToAny(jsonData []byte) (*anypb.Any, error) {
	// Create an empty Any
	anyMsg := &anypb.Any{}

	// Use protojson's Unmarshal which handles @type automatically
	if err := protojson.Unmarshal(jsonData, anyMsg); err != nil {
		return nil, err
	}
	return anyMsg, nil
}

func GetActionsFromValues(standardActions *string, customActions *string) []*policy.Action {
	var actions []*policy.Action
	if standardActions != nil {
		for value := range strings.SplitSeq(*standardActions, ",") {
			trimValue := strings.TrimSpace(value)
			if trimValue != "" {
				action := &policy.Action{
					Name: strings.ToLower(trimValue),
				}
				actions = append(actions, action)
			}
		}
	}
	if customActions != nil {
		for value := range strings.SplitSeq(*customActions, ",") {
			trimValue := strings.TrimSpace(value)
			if trimValue != "" {
				v := "CUSTOM_ACTION_" + trimValue
				actions = append(actions, &policy.Action{
					Name: strings.ToLower(v),
				})
			}
		}
	}
	return actions
}

func (s *AuthorizationServiceStepDefinitions) createEntity(referenceID string, entityCategory string, entityIDType string, entityIDValue string) (*entity.Entity, error) {
	ent := &entity.Entity{
		EphemeralId: referenceID,
		Category:    entity.Entity_Category(entity.Entity_Category_value["CATEGORY_"+entityCategory]),
	}
	// v2 entity types: email_address|user_name|claims|client_id
	switch entityIDType {
	case "email_address":
		ent.EntityType = &entity.Entity_EmailAddress{EmailAddress: entityIDValue}
	case "user_name":
		ent.EntityType = &entity.Entity_UserName{UserName: entityIDValue}
	case "claims":
		claims, err := ConvertInterfaceToAny([]byte(entityIDValue))
		if err != nil {
			return ent, err
		}
		ent.EntityType = &entity.Entity_Claims{Claims: claims}
	case "client_id":
		ent.EntityType = &entity.Entity_ClientId{ClientId: entityIDValue}
	default:
		return ent, fmt.Errorf("unsupported entity type: %s (v2 only supports: email_address, user_name, claims, client_id)", entityIDType)
	}
	return ent, nil
}

func (s *AuthorizationServiceStepDefinitions) thereIsAEnvEntityWithValueAndReferencedAs(ctx context.Context, entityIDType string, entityIDValue string, referenceID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	entity, err := s.createEntity(referenceID, "ENVIRONMENT", entityIDType, entityIDValue)
	if err != nil {
		return ctx, err
	}
	scenarioContext.RecordObject(referenceID, entity)
	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) thereIsASubjectEntityWithValueAndReferencedAs(ctx context.Context, entityIDType string, entityIDValue string, referenceID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	entity, err := s.createEntity(referenceID, "SUBJECT", entityIDType, entityIDValue)
	if err != nil {
		return ctx, err
	}
	scenarioContext.RecordObject(referenceID, entity)
	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) iSendADecisionRequestForEntityChainForActionOnResource(ctx context.Context, entityChainID, action, resource string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Send decision request using v2 API (with obligations support)
	err := s.sendDecisionRequestV2(ctx, scenarioContext, entityChainID, action, resource)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) iSendADecisionRequestForEntityChainForActionOnResourceWithFulfillableObligations(ctx context.Context, entityChainID, action, resource, fulfillableObligations string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	obligationFQNs := parseFqnsList(fulfillableObligations)
	err := s.sendDecisionRequestV2WithFulfillableObligations(ctx, scenarioContext, entityChainID, action, resource, obligationFQNs)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) iSendADecisionRequestForEntityChainForActionOnResourceWithNoFulfillableObligations(ctx context.Context, entityChainID, action, resource string) (context.Context, error) {
	return s.iSendADecisionRequestForEntityChainForActionOnResourceWithFulfillableObligations(ctx, entityChainID, action, resource, "[]")
}

// Step: I send a multi-resource decision request for entity chain "id" for "action" action on resources: (table)
func (s *AuthorizationServiceStepDefinitions) iSendAMultiResourceDecisionRequestForEntityChainForActionOnResources(ctx context.Context, entityChainID string, action string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	entityChain, err := buildEntityChainFromIDs(scenarioContext, entityChainID)
	if err != nil {
		return ctx, err
	}

	resources, resourceFQNMap, err := buildResourcesFromTable(tbl)
	if err != nil {
		return ctx, err
	}

	// Create v2 multi-resource decision request
	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{
				EntityChain: entityChain,
			},
		},
		Action: &policy.Action{
			Name: strings.ToLower(action),
		},
		Resources: resources,
		// For testing purposes, we declare that we can fulfill all obligations
		FulfillableObligationFqns: getAllObligationsFromScenario(scenarioContext),
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecisionMultiResource(ctx, req)

	scenarioContext.SetError(err)
	scenarioContext.RecordObject(multiDecisionResponseKey, resp)
	scenarioContext.RecordObject(decisionResponse, resp)
	scenarioContext.RecordObject("resourceFQNMap", resourceFQNMap)

	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) iSendAMultiResourceDecisionRequestForEntityChainForActionOnResourcesWithNoFulfillableObligations(ctx context.Context, entityChainID string, action string, tbl *godog.Table) (context.Context, error) {
	return s.iSendAMultiResourceDecisionRequestForEntityChainForActionOnResourcesWithFulfillableObligations(ctx, entityChainID, action, "[]", tbl)
}

func (s *AuthorizationServiceStepDefinitions) iSendAMultiResourceDecisionRequestForEntityChainForActionOnResourcesWithFulfillableObligations(ctx context.Context, entityChainID string, action string, fulfillableObligations string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	entityChain, err := buildEntityChainFromIDs(scenarioContext, entityChainID)
	if err != nil {
		return ctx, err
	}

	resources, resourceFQNMap, err := buildResourcesFromTable(tbl)
	if err != nil {
		return ctx, err
	}

	obligationFQNs := parseFqnsList(fulfillableObligations)
	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{
				EntityChain: entityChain,
			},
		},
		Action: &policy.Action{
			Name: strings.ToLower(action),
		},
		Resources:                 resources,
		FulfillableObligationFqns: obligationFQNs,
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecisionMultiResource(ctx, req)

	scenarioContext.SetError(err)
	scenarioContext.RecordObject(multiDecisionResponseKey, resp)
	scenarioContext.RecordObject(decisionResponse, resp)
	scenarioContext.RecordObject("resourceFQNMap", resourceFQNMap)

	return ctx, nil
}

// Send decision request using v2 API (with obligations support)
func (s *AuthorizationServiceStepDefinitions) sendDecisionRequestV2(ctx context.Context, scenarioContext *PlatformScenarioContext, entityChainID string, action string, resource string) error {
	return s.sendDecisionRequestV2WithFulfillableObligations(ctx, scenarioContext, entityChainID, action, resource, getAllObligationsFromScenario(scenarioContext))
}

func (s *AuthorizationServiceStepDefinitions) sendDecisionRequestV2WithFulfillableObligations(ctx context.Context, scenarioContext *PlatformScenarioContext, entityChainID string, action string, resource string, fulfillableObligations []string) error {
	// Build entity chain from stored v2 entities
	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		ent, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*entity.Entity)
		if !ok {
			return errors.New("object not of expected type Entity")
		}
		entities = append(entities, ent)
	}

	entityChain := &entity.EntityChain{
		Entities: entities,
	}

	// Parse resource FQNs
	var resourceFQNs []string
	for r := range strings.SplitSeq(resource, ",") {
		resourceFQNs = append(resourceFQNs, strings.TrimSpace(r))
	}

	// Create v2 decision request
	req := &authzV2.GetDecisionRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{
				EntityChain: entityChain,
			},
		},
		Action: &policy.Action{
			Name: strings.ToLower(action),
		},
		Resource: &authzV2.Resource{
			EphemeralId: "resource1",
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: resourceFQNs,
				},
			},
		},
		FulfillableObligationFqns: fulfillableObligations,
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecision(ctx, req)
	if err != nil {
		return err
	}

	scenarioContext.RecordObject(decisionResponse, resp)
	return nil
}

// Helper to get all obligation value FQNs from the scenario context
func getAllObligationsFromScenario(scenarioContext *PlatformScenarioContext) []string {
	var obligationFQNs []string

	// Get all obligations stored in the scenario context
	for _, obj := range scenarioContext.objects {
		if obligation, ok := obj.(*policy.Obligation); ok {
			// For each obligation, add all its value FQNs
			for _, ov := range obligation.GetValues() {
				obligationFQNs = append(obligationFQNs, ov.GetFqn())
			}
		}
	}

	return obligationFQNs
}

func buildEntityChainFromIDs(scenarioContext *PlatformScenarioContext, entityChainID string) (*entity.EntityChain, error) {
	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		ent, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*entity.Entity)
		if !ok {
			return nil, fmt.Errorf("entity %s not found or invalid type", entityID)
		}
		entities = append(entities, ent)
	}

	return &entity.EntityChain{Entities: entities}, nil
}

func buildResourcesFromTable(tbl *godog.Table) ([]*authzV2.Resource, map[string]string, error) {
	var resources []*authzV2.Resource
	resourceFQNMap := make(map[string]string)
	resourceIdx := 0
	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue
		}
		for _, cell := range row.Cells {
			fqn := strings.TrimSpace(cell.Value)
			ephemeralID := fmt.Sprintf("resource%d", resourceIdx)
			resourceFQNMap[ephemeralID] = fqn
			resources = append(resources, &authzV2.Resource{
				EphemeralId: ephemeralID,
				Resource: &authzV2.Resource_AttributeValues_{
					AttributeValues: &authzV2.Resource_AttributeValues{
						Fqns: []string{fqn},
					},
				},
			})
			resourceIdx++
		}
	}

	if len(resources) == 0 {
		return nil, nil, errors.New("no resources provided")
	}

	return resources, resourceFQNMap, nil
}

func parseFqnsList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" || strings.EqualFold(raw, "none") || strings.EqualFold(raw, "null") {
		return nil
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"))
		if raw == "" {
			return nil
		}
	}
	if raw == "" {
		return nil
	}
	out := make([]string, 0)
	for f := range strings.SplitSeq(raw, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Step: I should get N decision responses
func (s *AuthorizationServiceStepDefinitions) iShouldGetNDecisionResponses(ctx context.Context, count int) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	decisionRespV2, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok {
		decisionRespV2, ok = scenarioContext.GetObject(decisionResponse).(*authzV2.GetDecisionMultiResourceResponse)
		if !ok {
			return ctx, errors.New("multi-decision response not found or invalid")
		}
	}

	actualCount := len(decisionRespV2.GetResourceDecisions())
	if actualCount != count {
		return ctx, fmt.Errorf("expected %d decision responses, got %d", count, actualCount)
	}

	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) iShouldGetADecisionResponse(ctx context.Context, expectedResponse string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Try v2 single-resource response first
	if getDecisionsResponseV2, ok := scenarioContext.GetObject(decisionResponse).(*authzV2.GetDecisionResponse); ok {
		expectedResponse = "DECISION_" + expectedResponse
		actualDecision := getDecisionsResponseV2.GetDecision().GetDecision().String()
		if expectedResponse != actualDecision {
			return ctx, fmt.Errorf("unexpected response: %s instead of %s", actualDecision, expectedResponse)
		}
		return ctx, nil
	}

	// Try v2 multi-resource response (check first resource decision)
	if getDecisionsResponseV2Multi, ok := scenarioContext.GetObject(decisionResponse).(*authzV2.GetDecisionMultiResourceResponse); ok {
		if len(getDecisionsResponseV2Multi.GetResourceDecisions()) == 0 {
			return ctx, errors.New("no resource decisions found in multi-resource response")
		}
		expectedResponse = "DECISION_" + expectedResponse
		actualDecision := getDecisionsResponseV2Multi.GetResourceDecisions()[0].GetDecision().String()
		if expectedResponse != actualDecision {
			return ctx, fmt.Errorf("unexpected response: %s instead of %s", actualDecision, expectedResponse)
		}
		return ctx, nil
	}

	return ctx, errors.New("decision response not found or invalid")
}

// Step: the multi-resource decision should be "PERMIT" or "DENY"
func (s *AuthorizationServiceStepDefinitions) theMultiResourceDecisionShouldBe(ctx context.Context, expectedDecision string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	resp, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok {
		resp, ok = scenarioContext.GetObject(decisionResponse).(*authzV2.GetDecisionMultiResourceResponse)
		if !ok {
			return ctx, errors.New("multi-decision response not found or invalid")
		}
	}

	allPermitted := resp.GetAllPermitted()
	if allPermitted == nil {
		return ctx, errors.New("multi-decision missing all_permitted flag")
	}

	expected := strings.EqualFold(expectedDecision, "PERMIT")
	if allPermitted.GetValue() != expected {
		return ctx, fmt.Errorf("unexpected multi-decision result: got %v expected %v", allPermitted.GetValue(), expected)
	}

	return ctx, nil
}

// Step: the decision response for resource FQN should be "PERMIT" or "DENY"
func (s *AuthorizationServiceStepDefinitions) theDecisionResponseForResourceShouldBe(ctx context.Context, resourceFQN string, expectedDecision string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	decisionRespV2, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok {
		decisionRespV2, ok = scenarioContext.GetObject(decisionResponse).(*authzV2.GetDecisionMultiResourceResponse)
		if !ok {
			return ctx, errors.New("multi-decision response not found or invalid")
		}
	}

	resourceFQNMap, ok := scenarioContext.GetObject("resourceFQNMap").(map[string]string)
	if !ok || len(resourceFQNMap) == 0 {
		return ctx, errors.New("resourceFQNMap not found or empty")
	}

	expectedDecision = "DECISION_" + strings.ToUpper(strings.TrimSpace(expectedDecision))
	for _, rd := range decisionRespV2.GetResourceDecisions() {
		if fqn, exists := resourceFQNMap[rd.GetEphemeralResourceId()]; exists && fqn == resourceFQN {
			actualDecision := rd.GetDecision().String()
			if actualDecision != expectedDecision {
				return ctx, fmt.Errorf("unexpected decision for resource %s: %s instead of %s", resourceFQN, actualDecision, expectedDecision)
			}
			return ctx, nil
		}
	}

	known := make([]string, 0, len(resourceFQNMap))
	for _, fqn := range resourceFQNMap {
		known = append(known, fqn)
	}
	return ctx, fmt.Errorf("resource %s not found in decision responses (known: %v)", resourceFQN, known)
}

func RegisterAuthorizationStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := AuthorizationServiceStepDefinitions{}
	ctx.Step(`^there is a "([^"]*)" subject entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsASubjectEntityWithValueAndReferencedAs)
	ctx.Step(`^there is a "([^"]*)" environment entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsAEnvEntityWithValueAndReferencedAs)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on resource "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnResource)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on resource "([^"]*)" with fulfillable obligations "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnResourceWithFulfillableObligations)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on resource "([^"]*)" with no fulfillable obligations$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnResourceWithNoFulfillableObligations)
	ctx.Step(`^I send a multi-resource decision request for entity chain "([^"]*)" for "([^"]*)" action on resources:$`, stepDefinitions.iSendAMultiResourceDecisionRequestForEntityChainForActionOnResources)
	ctx.Step(`^I send a multi-resource decision request for entity chain "([^"]*)" for "([^"]*)" action on resources with no fulfillable obligations:$`, stepDefinitions.iSendAMultiResourceDecisionRequestForEntityChainForActionOnResourcesWithNoFulfillableObligations)
	ctx.Step(`^I send a multi-resource decision request for entity chain "([^"]*)" for "([^"]*)" action on resources with fulfillable obligations "([^"]*)":$`, stepDefinitions.iSendAMultiResourceDecisionRequestForEntityChainForActionOnResourcesWithFulfillableObligations)
	ctx.Step(`^I should get a "([^"]*)" decision response$`, stepDefinitions.iShouldGetADecisionResponse)
	ctx.Step(`^I should get (\d+) decision responses$`, stepDefinitions.iShouldGetNDecisionResponses)
	ctx.Step(`^the multi-resource decision should be "([^"]*)"$`, stepDefinitions.theMultiResourceDecisionShouldBe)
	ctx.Step(`^the decision response for resource "([^"]*)" should be "([^"]*)"$`, stepDefinitions.theDecisionResponseForResourceShouldBe)
}
