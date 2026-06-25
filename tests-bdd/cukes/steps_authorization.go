package cukes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type AuthorizationServiceStepDefinitions struct{}

const (
	decisionResponse                    = "decisionResponse"
	directEntitlementColumnAttributeFQN = "attribute_value_fqn"
	directEntitlementColumnActions      = "actions"
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

func (s *AuthorizationServiceStepDefinitions) thereIsAClaimsSubjectEntityReferencedAsWithDirectEntitlements(ctx context.Context, referenceID string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	directEntitlements, err := parseDirectEntitlementsTable(tbl)
	if err != nil {
		return ctx, err
	}

	claims := map[string]interface{}{
		"direct_entitlements": directEntitlements,
	}
	structClaims, err := structpb.NewStruct(claims)
	if err != nil {
		return ctx, err
	}
	anyClaims, err := anypb.New(structClaims)
	if err != nil {
		return ctx, err
	}

	entity := &entity.Entity{
		EphemeralId: referenceID,
		Category:    entity.Entity_CATEGORY_SUBJECT,
		EntityType:  &entity.Entity_Claims{Claims: anyClaims},
	}
	scenarioContext.RecordObject(referenceID, entity)
	return ctx, nil
}

func (s *AuthorizationServiceStepDefinitions) iAddClaimsToSubjectEntityWith(ctx context.Context, referenceID string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	entityObj, ok := scenarioContext.GetObject(referenceID).(*entity.Entity)
	if !ok || entityObj == nil {
		return ctx, fmt.Errorf("entity %s not found or invalid type", referenceID)
	}
	if entityObj.GetClaims() == nil {
		return ctx, errors.New("entity does not contain claims")
	}

	claimsStruct := &structpb.Struct{}
	if err := entityObj.GetClaims().UnmarshalTo(claimsStruct); err != nil {
		return ctx, err
	}
	claimsMap := claimsStruct.AsMap()

	updates, err := parseClaimsTable(tbl)
	if err != nil {
		return ctx, err
	}
	for key, value := range updates {
		claimsMap[key] = value
	}

	updatedStruct, err := structpb.NewStruct(claimsMap)
	if err != nil {
		return ctx, err
	}
	anyClaims, err := anypb.New(updatedStruct)
	if err != nil {
		return ctx, err
	}

	entityObj.EntityType = &entity.Entity_Claims{Claims: anyClaims}
	scenarioContext.RecordObject(referenceID, entityObj)
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

func parseDirectEntitlementsTable(tbl *godog.Table) ([]interface{}, error) {
	if tbl == nil || len(tbl.Rows) == 0 {
		return nil, errors.New("direct entitlements table is empty")
	}

	cellMap := map[string]int{}
	for ri, row := range tbl.Rows {
		if ri == 0 {
			for ci, cell := range row.Cells {
				cellMap[cell.Value] = ci
			}
			break
		}
	}

	attrIdx, ok := cellMap[directEntitlementColumnAttributeFQN]
	if !ok {
		return nil, fmt.Errorf("direct entitlements table requires column %s", directEntitlementColumnAttributeFQN)
	}
	actionsIdx, ok := cellMap[directEntitlementColumnActions]
	if !ok {
		return nil, fmt.Errorf("direct entitlements table requires column %s", directEntitlementColumnActions)
	}

	out := make([]interface{}, 0, len(tbl.Rows)-1)
	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue
		}
		attrFQN := strings.TrimSpace(row.Cells[attrIdx].Value)
		if attrFQN == "" {
			return nil, errors.New("direct entitlements require attribute_value_fqn values")
		}

		rawActions := ""
		if actionsIdx < len(row.Cells) {
			rawActions = row.Cells[actionsIdx].Value
		}
		actions := make([]interface{}, 0)
		for _, action := range strings.Split(rawActions, ",") {
			action = strings.TrimSpace(action)
			if action == "" {
				continue
			}
			actions = append(actions, strings.ToLower(action))
		}
		if len(actions) == 0 {
			return nil, fmt.Errorf("direct entitlement for %s requires actions", attrFQN)
		}

		out = append(out, map[string]interface{}{
			"attribute_value_fqn": attrFQN,
			"actions":             actions,
		})
	}

	if len(out) == 0 {
		return nil, errors.New("direct entitlements table has no rows")
	}

	return out, nil
}

func parseClaimsTable(tbl *godog.Table) (map[string]interface{}, error) {
	if tbl == nil || len(tbl.Rows) == 0 {
		return nil, errors.New("claims table is empty")
	}

	cellMap := map[string]int{}
	for ri, row := range tbl.Rows {
		if ri == 0 {
			for ci, cell := range row.Cells {
				cellMap[cell.Value] = ci
			}
			break
		}
	}

	nameIdx, ok := cellMap["name"]
	if !ok {
		return nil, errors.New("claims table requires column name")
	}
	valueIdx, ok := cellMap["value"]
	if !ok {
		return nil, errors.New("claims table requires column value")
	}

	out := map[string]interface{}{}
	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue
		}
		key := strings.TrimSpace(row.Cells[nameIdx].Value)
		if key == "" {
			return nil, errors.New("claims table requires name values")
		}
		rawValue := ""
		if valueIdx < len(row.Cells) {
			rawValue = strings.TrimSpace(row.Cells[valueIdx].Value)
		}

		var parsed interface{}
		if rawValue != "" {
			if err := json.Unmarshal([]byte(rawValue), &parsed); err != nil {
				parsed = rawValue
			}
		}
		out[key] = parsed
	}

	if len(out) == 0 {
		return nil, errors.New("claims table has no rows")
	}

	return out, nil
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
	ctx.Step(`^there is a claims subject entity referenced as "([^"]*)" with direct entitlements:$`, stepDefinitions.thereIsAClaimsSubjectEntityReferencedAsWithDirectEntitlements)
	ctx.Step(`^I add claims to subject entity "([^"]*)" with:$`, stepDefinitions.iAddClaimsToSubjectEntityWith)
	ctx.Step(`^there is a "([^"]*)" environment entity with value "([^"]*)" and referenced as "([^"]*)"$`, stepDefinitions.thereIsAEnvEntityWithValueAndReferencedAs)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on resource "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnResource)
	ctx.Step(`^I should get a "([^"]*)" decision response$`, stepDefinitions.iShouldGetADecisionResponse)
}
