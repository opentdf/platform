package cukes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/authorization"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
)

type ObligationsStepDefinitions struct{}

const (
	obligationResponseKey        = "obligationResponse"
	obligationTriggerResponseKey = "obligationTriggerResponse"
	multiDecisionResponseKey     = "multiDecisionResponse"
	valuesKey                    = "values"
)

// Step: I send a request to create an obligation with table
func (s *ObligationsStepDefinitions) iSendARequestToCreateAnObligationWith(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	cellIndexMap := make(map[int]string)
	for ri, r := range tbl.Rows {
		if ri == 0 {
			for ci, c := range r.Cells {
				cellIndexMap[ci] = c.Value
			}
			continue
		}

		req := &obligations.CreateObligationRequest{}
		var obligationName string
		var values []string

		for ci, c := range r.Cells {
			switch cellIndexMap[ci] {
			case "namespace_id":
				nsID, ok := scenarioContext.GetObject(strings.TrimSpace(c.Value)).(string)
				if !ok {
					return ctx, fmt.Errorf("namespace_id %s not found", c.Value)
				}
				req.NamespaceId = nsID
			case "name":
				obligationName = strings.TrimSpace(c.Value)
				req.Name = obligationName
			case valuesKey:
				if c.Value != "" {
					for _, v := range strings.Split(c.Value, ",") {
						values = append(values, strings.TrimSpace(v))
					}
					req.Values = values
				}
			}
		}

		resp, err := scenarioContext.SDK.Obligations.CreateObligation(ctx, req)
		scenarioContext.SetError(err)
		if err == nil && resp != nil {
			scenarioContext.RecordObject(obligationResponseKey, resp)
			scenarioContext.RecordObject(obligationName, resp.GetObligation())
		}
	}

	return ctx, nil
}

// Step: the obligation "name" should exist with values "value1,value2"
func (s *ObligationsStepDefinitions) theObligationShouldExistWithValues(ctx context.Context, name string, valuesStr string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	obligationObj := scenarioContext.GetObject(name)
	if obligationObj == nil {
		return ctx, fmt.Errorf("obligation %s not found", name)
	}

	obligation, ok := obligationObj.(*policy.Obligation)
	if !ok {
		return ctx, errors.New("object is not an obligation")
	}

	expectedValues := make(map[string]bool)
	for _, v := range strings.Split(valuesStr, ",") {
		expectedValues[strings.TrimSpace(v)] = false
	}

	for _, ov := range obligation.GetValues() {
		if _, exists := expectedValues[ov.GetValue()]; exists {
			expectedValues[ov.GetValue()] = true
		}
	}

	for v, found := range expectedValues {
		if !found {
			return ctx, fmt.Errorf("expected obligation value %s not found", v)
		}
	}

	return ctx, nil
}

// Step: I send a request to create an obligation trigger with table
func (s *ObligationsStepDefinitions) iSendARequestToCreateAnObligationTriggerWith(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	return s.createObligationTrigger(ctx, tbl, "")
}

// Step: I send a request to create an obligation trigger scoped to client "clientID" with table
func (s *ObligationsStepDefinitions) iSendARequestToCreateAnObligationTriggerScopedToClientWith(ctx context.Context, clientID string, tbl *godog.Table) (context.Context, error) {
	return s.createObligationTrigger(ctx, tbl, clientID)
}

func (s *ObligationsStepDefinitions) createObligationTrigger(ctx context.Context, tbl *godog.Table, clientID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	cellIndexMap := make(map[int]string)
	for ri, r := range tbl.Rows {
		if ri == 0 {
			for ci, c := range r.Cells {
				cellIndexMap[ci] = c.Value
			}
			continue
		}

		var obligationName, obligationValue, actionName, attributeValueFQN string

		for ci, c := range r.Cells {
			switch cellIndexMap[ci] {
			case "obligation_name":
				obligationName = strings.TrimSpace(c.Value)
			case "obligation_value":
				obligationValue = strings.TrimSpace(c.Value)
			case "action":
				actionName = strings.TrimSpace(c.Value)
			case "attribute_value":
				attributeValueFQN = strings.TrimSpace(c.Value)
			}
		}

		// Get the obligation
		obligationObj := scenarioContext.GetObject(obligationName)
		if obligationObj == nil {
			return ctx, fmt.Errorf("obligation %s not found", obligationName)
		}
		obligation, ok := obligationObj.(*policy.Obligation)
		if !ok {
			return ctx, errors.New("object is not an obligation")
		}

		// Find the obligation value
		var obligationValueObj *policy.ObligationValue
		for _, ov := range obligation.GetValues() {
			if ov.GetValue() == obligationValue {
				obligationValueObj = ov
				break
			}
		}
		if obligationValueObj == nil {
			return ctx, fmt.Errorf("obligation value %s not found in obligation %s", obligationValue, obligationName)
		}

		// Get attribute value
		attributeValue, err := scenarioContext.GetAttributeValue(ctx, attributeValueFQN)
		if err != nil {
			return ctx, fmt.Errorf("failed to get attribute value: %w", err)
		}

		// Create the trigger request
		req := &obligations.AddObligationTriggerRequest{
			ObligationValue: &common.IdFqnIdentifier{
				Id: obligationValueObj.GetId(),
			},
			Action: &common.IdNameIdentifier{
				Name: actionName,
			},
			AttributeValue: &common.IdFqnIdentifier{
				Id: attributeValue.GetId(),
			},
		}

		// Add client ID scope if provided
		if clientID != "" {
			req.Context = &policy.RequestContext{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			}
		}

		resp, err := scenarioContext.SDK.Obligations.AddObligationTrigger(ctx, req)
		scenarioContext.SetError(err)
		if err == nil && resp != nil {
			scenarioContext.RecordObject(obligationTriggerResponseKey, resp)
		}
	}

	return ctx, nil
}

// Step: the decision response should contain obligation "fqn"
func (s *ObligationsStepDefinitions) theDecisionResponseShouldContainObligation(ctx context.Context, obligationFQN string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Try v2 single-resource response first
	if decisionRespV2, ok := scenarioContext.GetObject("decisionResponse").(*authzV2.GetDecisionResponse); ok {
		obligations := decisionRespV2.GetDecision().GetRequiredObligations()
		for _, obl := range obligations {
			if obl == obligationFQN {
				return ctx, nil
			}
		}
		return ctx, fmt.Errorf("obligation %s not found in decision response. Found: %v", obligationFQN, obligations)
	}

	// Try v2 multi-resource response
	if decisionRespV2Multi, ok := scenarioContext.GetObject("decisionResponse").(*authzV2.GetDecisionMultiResourceResponse); ok {
		if len(decisionRespV2Multi.GetResourceDecisions()) == 0 {
			return ctx, errors.New("no resource decisions found")
		}
		obligations := decisionRespV2Multi.GetResourceDecisions()[0].GetRequiredObligations()
		for _, obl := range obligations {
			if obl == obligationFQN {
				return ctx, nil
			}
		}
		return ctx, fmt.Errorf("obligation %s not found in decision response. Found: %v", obligationFQN, obligations)
	}

	return ctx, errors.New("decision response not found or invalid")
}

// Step: the decision response should not contain obligation "fqn"
func (s *ObligationsStepDefinitions) theDecisionResponseShouldNotContainObligation(ctx context.Context, obligationFQN string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Try v2 single-resource response first
	if decisionRespV2, ok := scenarioContext.GetObject("decisionResponse").(*authzV2.GetDecisionResponse); ok {
		obligations := decisionRespV2.GetDecision().GetRequiredObligations()
		for _, obl := range obligations {
			if obl == obligationFQN {
				return ctx, fmt.Errorf("obligation %s should not be in decision response", obligationFQN)
			}
		}
		return ctx, nil
	}

	return ctx, errors.New("decision response not found or invalid")
}

// Step: I send a multi-resource decision request for entity chain "id" for "action" action on resources: (table)
func (s *ObligationsStepDefinitions) iSendAMultiResourceDecisionRequestForEntityChainForActionOnResources(ctx context.Context, entityChainID string, action string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	// Build entity chain for v2 API
	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		v1Entity, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*authorization.Entity)
		if !ok {
			return ctx, fmt.Errorf("entity %s not found or invalid type", entityID)
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

	// Parse resource FQNs from table
	var resources []*authzV2.Resource
	resourceFQNMap := make(map[string]string) // map ephemeral ID to FQN
	resourceIdx := 0
	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue // Skip header
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
	scenarioContext.RecordObject("decisionResponse", resp)         // Also store as single response for compatibility
	scenarioContext.RecordObject("resourceFQNMap", resourceFQNMap) // Store mapping for validation

	return ctx, nil
}

// Step: I should get N decision responses
func (s *ObligationsStepDefinitions) iShouldGetNDecisionResponses(ctx context.Context, count int) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Check v2 multi-resource response
	decisionRespV2, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok {
		return ctx, errors.New("multi-decision response not found or invalid")
	}

	actualCount := len(decisionRespV2.GetResourceDecisions())
	if actualCount != count {
		return ctx, fmt.Errorf("expected %d decision responses, got %d", count, actualCount)
	}

	return ctx, nil
}

// Step: the decision response for resource "fqn" should contain obligation "obligation_fqn"
func (s *ObligationsStepDefinitions) theDecisionResponseForResourceShouldContainObligation(ctx context.Context, resourceFQN string, obligationFQN string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Check v2 multi-resource response
	decisionRespV2, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok {
		return ctx, errors.New("multi-decision response not found or invalid")
	}

	// Get the FQN map to find the ephemeral ID for this resource
	resourceFQNMap, _ := scenarioContext.GetObject("resourceFQNMap").(map[string]string)

	// Find the resource decision by matching FQN
	for _, rd := range decisionRespV2.GetResourceDecisions() {
		// Check if this resource decision matches our FQN
		if fqn, exists := resourceFQNMap[rd.GetEphemeralResourceId()]; exists && fqn == resourceFQN {
			for _, obl := range rd.GetRequiredObligations() {
				if obl == obligationFQN {
					return ctx, nil
				}
			}
			return ctx, fmt.Errorf("obligation %s not found for resource %s. Found: %v", obligationFQN, resourceFQN, rd.GetRequiredObligations())
		}
	}
	return ctx, fmt.Errorf("resource %s not found in decision responses", resourceFQN)
}

// Step: the decision response for resource "fqn" should not contain any obligations
func (s *ObligationsStepDefinitions) theDecisionResponseForResourceShouldNotContainAnyObligations(ctx context.Context, resourceFQN string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	// Check v2 multi-resource response
	decisionRespV2, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok {
		return ctx, errors.New("multi-decision response not found or invalid")
	}

	// Get the FQN map to find the ephemeral ID for this resource
	resourceFQNMap, _ := scenarioContext.GetObject("resourceFQNMap").(map[string]string)

	// Find the resource decision by matching FQN
	for _, rd := range decisionRespV2.GetResourceDecisions() {
		// Check if this resource decision matches our FQN
		if fqn, exists := resourceFQNMap[rd.GetEphemeralResourceId()]; exists && fqn == resourceFQN {
			if len(rd.GetRequiredObligations()) > 0 {
				return ctx, fmt.Errorf("expected no obligations for resource %s, but found: %v", resourceFQN, rd.GetRequiredObligations())
			}
			return ctx, nil
		}
	}
	return ctx, fmt.Errorf("resource %s not found in decision responses", resourceFQN)
}

// Step: the decision response should contain obligations: (table)
func (s *ObligationsStepDefinitions) theDecisionResponseShouldContainObligations(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	var actualObligations map[string]bool

	// Try v2 single-resource response first
	if decisionRespV2, singleOK := scenarioContext.GetObject("decisionResponse").(*authzV2.GetDecisionResponse); singleOK {
		actualObligations = make(map[string]bool)
		if decisionRespV2.GetDecision() != nil {
			for _, obl := range decisionRespV2.GetDecision().GetRequiredObligations() {
				actualObligations[obl] = true
			}
		}
	} else if decisionRespV2Multi, multiOK := scenarioContext.GetObject("decisionResponse").(*authzV2.GetDecisionMultiResourceResponse); multiOK {
		// Try v2 multi-resource response
		if len(decisionRespV2Multi.GetResourceDecisions()) == 0 {
			return ctx, errors.New("no resource decisions found")
		}
		actualObligations = make(map[string]bool)
		for _, obl := range decisionRespV2Multi.GetResourceDecisions()[0].GetRequiredObligations() {
			actualObligations[obl] = true
		}
	} else {
		return ctx, errors.New("decision response not found or invalid")
	}

	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue // Skip header
		}
		expectedObligation := strings.TrimSpace(row.Cells[0].Value)
		if !actualObligations[expectedObligation] {
			actualOblList := make([]string, 0, len(actualObligations))
			for obl := range actualObligations {
				actualOblList = append(actualOblList, obl)
			}
			return ctx, fmt.Errorf("expected obligation %s not found. Actual obligations: %v", expectedObligation, actualOblList)
		}
	}

	return ctx, nil
}

func RegisterObligationsStepDefinitions(ctx *godog.ScenarioContext, _ *PlatformTestSuiteContext) {
	stepDefinitions := ObligationsStepDefinitions{}

	// Obligation creation steps
	ctx.Step(`^I send a request to create an obligation with:$`, stepDefinitions.iSendARequestToCreateAnObligationWith)
	ctx.Step(`^the obligation "([^"]*)" should exist with values "([^"]*)"$`, stepDefinitions.theObligationShouldExistWithValues)

	// Obligation trigger creation steps
	ctx.Step(`^I send a request to create an obligation trigger with:$`, stepDefinitions.iSendARequestToCreateAnObligationTriggerWith)
	ctx.Step(`^I send a request to create an obligation trigger scoped to client "([^"]*)" with:$`, stepDefinitions.iSendARequestToCreateAnObligationTriggerScopedToClientWith)

	// Decision response validation steps
	ctx.Step(`^the decision response should contain obligation "([^"]*)"$`, stepDefinitions.theDecisionResponseShouldContainObligation)
	ctx.Step(`^the decision response should not contain obligation "([^"]*)"$`, stepDefinitions.theDecisionResponseShouldNotContainObligation)
	ctx.Step(`^the decision response should contain obligations:$`, stepDefinitions.theDecisionResponseShouldContainObligations)

	// Multi-resource decision steps
	ctx.Step(`^I send a multi-resource decision request for entity chain "([^"]*)" for "([^"]*)" action on resources:$`, stepDefinitions.iSendAMultiResourceDecisionRequestForEntityChainForActionOnResources)
	ctx.Step(`^I should get (\d+) decision responses$`, stepDefinitions.iShouldGetNDecisionResponses)
	ctx.Step(`^the decision response for resource "([^"]*)" should contain obligation "([^"]*)"$`, stepDefinitions.theDecisionResponseForResourceShouldContainObligation)
	ctx.Step(`^the decision response for resource "([^"]*)" should not contain any obligations$`, stepDefinitions.theDecisionResponseForResourceShouldNotContainAnyObligations)
}
