package cukes

import (
	"context"
	"encoding/json"
	"errors"
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
		Category: authorization.Entity_Category(authorization.Entity_Category_value["CATEGORY_"+entityCategory]),
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

	// Send decision request using v2 API (with obligations support)
	err := s.sendDecisionRequestV2(ctx, scenarioContext, entityChainID, action, resource)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

// Send decision request using v2 API (with obligations support)
func (s *AuthorizationServiceStepDefinitions) sendDecisionRequestV2(ctx context.Context, scenarioContext *PlatformScenarioContext, entityChainID string, action string, resource string) error {
	// Build entity chain for v2 API
	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		v1Entity, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*authorization.Entity)
		if !ok {
			return errors.New("object not of expected type Entity")
		}

		// Convert v1 Entity to v2 entity.Entity
		v2Entity := &entity.Entity{
			EphemeralId: v1Entity.GetId(),
			Category:    entity.Entity_Category(v1Entity.GetCategory()),
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

func RegisterAuthorizationStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := AuthorizationServiceStepDefinitions{}
	ctx.Step(`^there is a "([^"]*)" subject entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsASubjectEntityWithValueAndReferencedAs)
	ctx.Step(`^there is a "([^"]*)" environment entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsAEnvEntityWithValueAndReferencedAs)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on resource "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnResource)
	ctx.Step(`^I should get a "([^"]*)" decision response$`, stepDefinitions.iShouldGetADecisionResponse)
}
