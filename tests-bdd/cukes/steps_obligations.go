package cukes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
)

type ObligationsStepDefinitions struct{}

const (
	obligationResponseKey        = "obligationResponse"
	obligationTriggerResponseKey = "obligationTriggerResponse"
	multiDecisionResponseKey     = "multiDecisionResponse"
	valuesKey                    = "values"
	nameKey                      = "name"
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
			case namespaceIDKey:
				nsID, ok := scenarioContext.GetObject(strings.TrimSpace(c.Value)).(string)
				if !ok {
					return ctx, fmt.Errorf("%s %s not found", namespaceIDKey, c.Value)
				}
				req.NamespaceId = nsID
			case nameKey:
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

// Step: the obligation name should exist with values "value1,value2"
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

// Step: the decision response should contain obligation FQN
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

// Step: the decision response should not contain obligation FQN
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

	// Try v2 multi-resource response
	if decisionRespV2Multi, ok := scenarioContext.GetObject("decisionResponse").(*authzV2.GetDecisionMultiResourceResponse); ok {
		if len(decisionRespV2Multi.GetResourceDecisions()) > 0 {
			for _, decision := range decisionRespV2Multi.GetResourceDecisions() {
				obligations := decision.GetRequiredObligations()
				for _, obl := range obligations {
					if obl == obligationFQN {
						return ctx, fmt.Errorf("obligation %s should not be in decision response for first resource", obligationFQN)
					}
				}
			}
		}
		return ctx, nil
	}

	return ctx, errors.New("decision response not found or invalid")
}

// Step: the decision response for resource FQN should contain obligation
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

// Step: the decision response for resource FQN should not contain any obligations
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
		// For multi-resource responses, validate obligations across ALL resource decisions
		if len(decisionRespV2Multi.GetResourceDecisions()) == 0 {
			return ctx, errors.New("no resource decisions found")
		}
		actualObligations = make(map[string]bool)
		for _, rd := range decisionRespV2Multi.GetResourceDecisions() {
			for _, obl := range rd.GetRequiredObligations() {
				actualObligations[obl] = true
			}
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

	ctx.Step(`^the decision response for resource "([^"]*)" should contain obligation "([^"]*)"$`, stepDefinitions.theDecisionResponseForResourceShouldContainObligation)
	ctx.Step(`^the decision response for resource "([^"]*)" should not contain any obligations$`, stepDefinitions.theDecisionResponseForResourceShouldNotContainAnyObligations)
}
