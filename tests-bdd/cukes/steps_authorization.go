package cukes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/authorization"
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
	// Parse the JSON to get the type
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &rawMsg); err != nil {
		return nil, err
	}

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

func (s *AuthorizationServiceStepDefinitions) createEntity(referenceID string, entityCategory string, entityIDType string, entityIDValue string) (*authorization.Entity, error) {
	entity := &authorization.Entity{
		Id:       referenceID,
		Category: authorization.Entity_Category(authorization.Entity_Category_value[fmt.Sprintf("CATEGORY_%s", entityCategory)]),
	}
	// email_address|user_name|remote_claims_url|uuid|claims|custom|client_id
	switch entityIDType {
	case "email_address":
		entity.EntityType = &authorization.Entity_EmailAddress{EmailAddress: entityIDValue}
	case "user_name":
		entity.EntityType = &authorization.Entity_UserName{UserName: entityIDValue}
	case "remote_claims_url":
		entity.EntityType = &authorization.Entity_RemoteClaimsUrl{RemoteClaimsUrl: entityIDValue}
	case "uuid":
		entity.EntityType = &authorization.Entity_Uuid{Uuid: entityIDValue}
	case "claims":
		claims, err := ConvertInterfaceToAny([]byte(entityIDValue))
		if err != nil {
			return entity, err
		}
		entity.EntityType = &authorization.Entity_Claims{Claims: claims}
	case "custom":
		// todo implement this
		entity.EntityType = &authorization.Entity_Custom{Custom: &authorization.EntityCustom{}}
	case "client_id":
		entity.EntityType = &authorization.Entity_ClientId{ClientId: entityIDValue}
	}
	return entity, nil
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
	
	// Try v2 API first (supports obligations)
	err := s.sendDecisionRequestV2(ctx, scenarioContext, entityChainID, action, resource)
	if err == nil {
		// v2 API succeeded, mark that we're using it
		scenarioContext.RecordObject("api_version", "v2")
		return ctx, nil
	}
	
	// Check if it's an "unimplemented" or "not found" error indicating v2 API is unavailable
	// If so, fall back to v1 API
	errStr := err.Error()
	if strings.Contains(errStr, "Unimplemented") || 
	   strings.Contains(errStr, "not found") ||
	   strings.Contains(errStr, "404") ||
	   strings.Contains(errStr, "unimplemented") {
		fmt.Printf("⚠️  Authorization v2 API not available, falling back to v1 (obligations not supported)\n")
		scenarioContext.RecordObject("api_version", "v1")
		return s.sendDecisionRequestV1(ctx, scenarioContext, entityChainID, action, resource)
	}
	
	// If it's a different error, return it
	return ctx, err
}

// Send decision request using v2 API (with obligations support)
func (s *AuthorizationServiceStepDefinitions) sendDecisionRequestV2(ctx context.Context, scenarioContext *PlatformScenarioContext, entityChainID string, action string, resource string) error {
	// Build entity chain for v2 API
	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		v1Entity, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*authorization.Entity)
		if !ok {
			return fmt.Errorf("object not of expected type Entity")
		}
		
		// Convert v1 Entity to v2 entity.Entity
		v2Entity := &entity.Entity{
			EphemeralId: v1Entity.GetId(),
			Category:    convertEntityCategoryToV2(v1Entity.GetCategory()),
		}
		
		// Convert entity type
		switch et := v1Entity.GetEntityType().(type) {
		case *authorization.Entity_EmailAddress:
			v2Entity.EntityType = &entity.Entity_EmailAddress{
				EmailAddress: et.EmailAddress,
			}
		case *authorization.Entity_UserName:
			v2Entity.EntityType = &entity.Entity_UserName{
				UserName: et.UserName,
			}
		case *authorization.Entity_Claims:
			v2Entity.EntityType = &entity.Entity_Claims{
				Claims: et.Claims,
			}
		case *authorization.Entity_ClientId:
			v2Entity.EntityType = &entity.Entity_ClientId{
				ClientId: et.ClientId,
			}
		}
		
		entities = append(entities, v2Entity)
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
		// For testing purposes, we declare that we can fulfill all obligations
		FulfillableObligationFqns: getAllObligationsFromScenario(scenarioContext),
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecision(ctx, req)
	if err != nil {
		return err
	}
	
	scenarioContext.RecordObject(decisionResponse, resp)
	return nil
}

// Send decision request using v1 API (legacy, no obligations support)
func (s *AuthorizationServiceStepDefinitions) sendDecisionRequestV1(ctx context.Context, scenarioContext *PlatformScenarioContext, entityChainID string, action string, resource string) (context.Context, error) {
	entityChain := &authorization.EntityChain{
		Entities: []*authorization.Entity{},
	}
	
	for _, entityID := range strings.Split(entityChainID, ",") {
		entity, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*authorization.Entity)
		if !ok {
			return ctx, fmt.Errorf("object not of expected type Entity")
		}
		entityChain.Entities = append(entityChain.Entities, entity)
	}
	
	var resourceFQNs []string
	for r := range strings.SplitSeq(resource, ",") {
		resourceFQNs = append(resourceFQNs, strings.TrimSpace(r))
	}
	
	resp, err := scenarioContext.SDK.Authorization.GetDecisions(ctx, &authorization.GetDecisionsRequest{
		DecisionRequests: []*authorization.DecisionRequest{
			{
				Actions: GetActionsFromValues(&action, nil),
				EntityChains: []*authorization.EntityChain{
					entityChain,
				},
				ResourceAttributes: []*authorization.ResourceAttribute{
					{
						AttributeValueFqns: resourceFQNs,
					},
				},
			},
		},
	})
	
	scenarioContext.SetError(err)
	scenarioContext.RecordObject(decisionResponse, resp)
	return ctx, nil
}

// Helper to get all obligation value FQNs from the scenario context
func getAllObligationsFromScenario(scenarioContext *PlatformScenarioContext) []string {
	var obligationFQNs []string
	
	// Get all obligations stored in the scenario context
	for key, obj := range scenarioContext.objects {
		if obligation, ok := obj.(*policy.Obligation); ok {
			// For each obligation, add all its value FQNs
			for _, ov := range obligation.GetValues() {
				obligationFQNs = append(obligationFQNs, ov.GetFqn())
			}
			_ = key // unused
		}
	}
	
	return obligationFQNs
}

// Helper function to convert v1 Entity Category to v2
func convertEntityCategoryToV2(v1Cat authorization.Entity_Category) entity.Entity_Category {
	switch v1Cat {
	case authorization.Entity_CATEGORY_SUBJECT:
		return entity.Entity_CATEGORY_SUBJECT
	case authorization.Entity_CATEGORY_ENVIRONMENT:
		return entity.Entity_CATEGORY_ENVIRONMENT
	default:
		return entity.Entity_CATEGORY_UNSPECIFIED
	}
}

func (s *AuthorizationServiceStepDefinitions) iShouldGetADecisionResponse(ctx context.Context, expectedResponse string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	
	// Try v2 response first
	if getDecisionsResponseV2, ok := scenarioContext.GetObject(decisionResponse).(*authzV2.GetDecisionResponse); ok {
		expectedResponse = "DECISION_" + expectedResponse
		actualDecision := getDecisionsResponseV2.GetDecision().GetDecision().String()
		if expectedResponse != actualDecision {
			return ctx, fmt.Errorf("unexpected response: %s instead of %s", actualDecision, expectedResponse)
		}
		return ctx, nil
	}
	
	// Fall back to v1 response
	getDecisionsResponse, ok := scenarioContext.GetObject(decisionResponse).(*authorization.GetDecisionsResponse)
	if !ok {
		return ctx, fmt.Errorf("object not of expected type getDecisionsResponse (v1 or v2)")
	}
	expectedResponse = "DECISION_" + expectedResponse
	if expectedResponse != getDecisionsResponse.GetDecisionResponses()[0].GetDecision().String() {
		return ctx, fmt.Errorf("unexpected response: %s instead of %s", getDecisionsResponse.GetDecisionResponses()[0].GetDecision().String(), expectedResponse)
	}
	return ctx, nil
}

// When I send a decision request with action "<action>" for resource "<resource>" and entity chain of "<subj_type>" "<subj_value>" and "<env_type>" and "<env_value>"
func (s *AuthorizationServiceStepDefinitions) iSendADecisionRequestWithActionForResAndEChainOfSubjAndEnv(ctx context.Context,
	action, resource, subjectType, subjectValue, envType, envValue string,
) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	entityChain := &authorization.EntityChain{
		Id:       "entity_chain_1",
		Entities: []*authorization.Entity{},
	}
	scenarioContext.ClearError()
	if strings.TrimSpace(subjectType) != "" {
		entity, err := s.createEntity("s1", "SUBJECT", subjectType, subjectValue)
		if err != nil {
			return ctx, err
		}
		entityChain.Entities = append(entityChain.Entities, entity)
	}
	if strings.TrimSpace(envType) != "" {
		entity, err := s.createEntity("e1", "ENVIRONMENT", envType, envValue)
		if err != nil {
			return ctx, err
		}
		entityChain.Entities = append(entityChain.Entities, entity)
	}
	var resourceFQNs []string
	for _, r := range strings.Split(resource, ",") {
		resourceFQNs = append(resourceFQNs, strings.TrimSpace(r))
	}
	resp, err := scenarioContext.SDK.Authorization.GetDecisions(ctx, &authorization.GetDecisionsRequest{
		DecisionRequests: []*authorization.DecisionRequest{
			{
				Actions: GetActionsFromValues(&action, nil),
				EntityChains: []*authorization.EntityChain{
					entityChain,
				},
				ResourceAttributes: []*authorization.ResourceAttribute{
					{
						AttributeValueFqns: resourceFQNs,
					},
				},
			},
		},
	})
	scenarioContext.SetError(err)
	scenarioContext.RecordObject(decisionResponse, resp)
	return ctx, nil
}

func RegisterAuthorizationStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := AuthorizationServiceStepDefinitions{}
	ctx.Step(`^there is a "([^"]*)" subject entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsASubjectEntityWithValueAndReferencedAs)
	ctx.Step(`^there is a "([^"]*)" environment entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsAEnvEntityWithValueAndReferencedAs)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on resource "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnResource)
	ctx.Step(`^I should get a "([^"]*)" decision response$`, stepDefinitions.iShouldGetADecisionResponse)
	ctx.Step(`^I send a decision request with action "([^"]*)" for resource "([^"]*)" and entity chain of "([^"]*)" with "([^"]*)" and "([^"]*)" with "([^"]*)"$`, stepDefinitions.iSendADecisionRequestWithActionForResAndEChainOfSubjAndEnv)
}
