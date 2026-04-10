package cukes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/lib/identifier"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
)

type RegisteredResourcesStepDefinitions struct{}

const (
	referenceIDColumn = "reference_id"
	aavPairParts      = 2
)

func resolveRegisteredResourceValueFQN(scenarioContext *PlatformScenarioContext, resourceValueRef string) (string, error) {
	resourceValueRef = strings.TrimSpace(resourceValueRef)
	if rrValue, ok := scenarioContext.GetObject(resourceValueRef).(*policy.RegisteredResourceValue); ok && rrValue != nil {
		if rrValue.GetResource() == nil {
			return "", fmt.Errorf("registered resource value %s missing resource", resourceValueRef)
		}
		namespaceName := ""
		if rrValue.GetResource().GetNamespace() != nil {
			namespaceName = rrValue.GetResource().GetNamespace().GetName()
		}
		return (&identifier.FullyQualifiedRegisteredResourceValue{
			Namespace: namespaceName,
			Name:      rrValue.GetResource().GetName(),
			Value:     rrValue.GetValue(),
		}).FQN(), nil
	}
	return resourceValueRef, nil
}

func (s *RegisteredResourcesStepDefinitions) iSendARequestToCreateARegisteredResourceWith(ctx context.Context, tbl *godog.Table) (context.Context, error) {
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

		req := &registeredresources.CreateRegisteredResourceRequest{}
		referenceID := ""

		for ci, c := range r.Cells {
			v := strings.TrimSpace(c.Value)
			switch cellIndexMap[ci] {
			case referenceIDColumn:
				referenceID = v
			case "name":
				req.Name = v
			case "namespace_id":
				nsID, ok := scenarioContext.GetObject(v).(string)
				if !ok {
					return ctx, fmt.Errorf("namespace_id %s not found", v)
				}
				req.NamespaceId = nsID
			case "namespace_fqn":
				req.NamespaceFqn = v
			}
		}

		resp, err := scenarioContext.SDK.RegisteredResources.CreateRegisteredResource(ctx, req)
		scenarioContext.SetError(err)
		if err == nil && resp != nil {
			if referenceID != "" {
				scenarioContext.RecordObject(referenceID, resp.GetResource())
			}
			scenarioContext.RecordObject(req.GetName(), resp.GetResource())
		}
	}

	return ctx, nil
}

func (s *RegisteredResourcesStepDefinitions) iSendARequestToCreateARegisteredResourceValueWith(ctx context.Context, tbl *godog.Table) (context.Context, error) {
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

		req := &registeredresources.CreateRegisteredResourceValueRequest{}
		referenceID := ""

		for ci, c := range r.Cells {
			v := strings.TrimSpace(c.Value)
			switch cellIndexMap[ci] {
			case referenceIDColumn:
				referenceID = v
			case "resource_ref":
				resource, ok := scenarioContext.GetObject(v).(*policy.RegisteredResource)
				if !ok || resource == nil {
					return ctx, fmt.Errorf("resource_ref %s not found", v)
				}
				req.ResourceId = resource.GetId()
			case "value":
				req.Value = v
			case "action_attribute_values":
				if v == "" {
					continue
				}
				aavs, err := parseAAVs(v)
				if err != nil {
					return ctx, err
				}
				req.ActionAttributeValues = aavs
			}
		}

		resp, err := scenarioContext.SDK.RegisteredResources.CreateRegisteredResourceValue(ctx, req)
		scenarioContext.SetError(err)
		if err == nil && resp != nil {
			if referenceID != "" {
				scenarioContext.RecordObject(referenceID, resp.GetValue())
			}
			scenarioContext.RecordObject(req.GetValue(), resp.GetValue())
		}
	}

	return ctx, nil
}

func parseAAVs(raw string) ([]*registeredresources.ActionAttributeValue, error) {
	parts := strings.Split(raw, ",")
	out := make([]*registeredresources.ActionAttributeValue, 0, len(parts))

	for _, part := range parts {
		entry := strings.TrimSpace(part)
		pair := strings.SplitN(entry, "=>", aavPairParts)
		if len(pair) != aavPairParts {
			pair = strings.SplitN(entry, "|", aavPairParts)
		}
		if len(pair) != aavPairParts {
			return nil, fmt.Errorf("invalid action_attribute_values entry %q, expected action=>attribute_value_fqn", part)
		}

		actionName := strings.TrimSpace(pair[0])
		attributeValueFQN := strings.TrimSpace(pair[1])
		if actionName == "" || attributeValueFQN == "" {
			return nil, fmt.Errorf("invalid action_attribute_values entry %q, action and attribute value fqn are required", part)
		}

		out = append(out, &registeredresources.ActionAttributeValue{
			ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
				ActionName: strings.ToLower(actionName),
			},
			AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
				AttributeValueFqn: attributeValueFQN,
			},
		})
	}

	return out, nil
}

func (s *RegisteredResourcesStepDefinitions) iSendADecisionRequestForEntityChainForActionOnRegisteredResourceValue(ctx context.Context, entityChainID string, action string, resourceValueRef string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		ent, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*entity.Entity)
		if !ok {
			return ctx, fmt.Errorf("entity %s not found or invalid type", entityID)
		}
		entities = append(entities, ent)
	}

	entityChain := &entity.EntityChain{Entities: entities}

	resourceValueFQN, err := resolveRegisteredResourceValueFQN(scenarioContext, resourceValueRef)
	if err != nil {
		return ctx, err
	}

	req := &authzV2.GetDecisionRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{EntityChain: entityChain},
		},
		Action: &policy.Action{Name: strings.ToLower(action)},
		Resource: &authzV2.Resource{
			EphemeralId: "resource1",
			Resource: &authzV2.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: resourceValueFQN,
			},
		},
		FulfillableObligationFqns: getAllObligationsFromScenario(scenarioContext),
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecision(ctx, req)
	if err != nil {
		scenarioContext.SetError(err)
		return ctx, err
	}

	scenarioContext.RecordObject(decisionResponse, resp)
	return ctx, nil
}

func (s *RegisteredResourcesStepDefinitions) iSendADecisionRequestForRegisteredResourceValueEntityForActionOnResource(ctx context.Context, entityValueRef string, action string, resource string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	entityFQN, err := resolveRegisteredResourceValueFQN(scenarioContext, entityValueRef)
	if err != nil {
		return ctx, err
	}

	var resourceFQNs []string
	for r := range strings.SplitSeq(resource, ",") {
		resourceFQNs = append(resourceFQNs, strings.TrimSpace(r))
	}

	req := &authzV2.GetDecisionRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: entityFQN,
			},
		},
		Action: &policy.Action{Name: strings.ToLower(action)},
		Resource: &authzV2.Resource{
			EphemeralId: "resource1",
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: resourceFQNs,
				},
			},
		},
		FulfillableObligationFqns: getAllObligationsFromScenario(scenarioContext),
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecision(ctx, req)
	if err != nil {
		scenarioContext.SetError(err)
		return ctx, err
	}

	scenarioContext.RecordObject(decisionResponse, resp)
	return ctx, nil
}

func (s *RegisteredResourcesStepDefinitions) iSendADecisionRequestForRegisteredResourceValueEntityForActionOnRegisteredResourceValue(ctx context.Context, entityValueRef string, action string, resourceValueRef string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	entityFQN, err := resolveRegisteredResourceValueFQN(scenarioContext, entityValueRef)
	if err != nil {
		return ctx, err
	}
	resourceFQN, err := resolveRegisteredResourceValueFQN(scenarioContext, resourceValueRef)
	if err != nil {
		return ctx, err
	}

	req := &authzV2.GetDecisionRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: entityFQN,
			},
		},
		Action: &policy.Action{Name: strings.ToLower(action)},
		Resource: &authzV2.Resource{
			EphemeralId: "resource1",
			Resource: &authzV2.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: resourceFQN,
			},
		},
		FulfillableObligationFqns: getAllObligationsFromScenario(scenarioContext),
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecision(ctx, req)
	if err != nil {
		scenarioContext.SetError(err)
		return ctx, err
	}

	scenarioContext.RecordObject(decisionResponse, resp)
	return ctx, nil
}

func (s *RegisteredResourcesStepDefinitions) iSendAMultiResourceDecisionRequestForEntityChainForActionOnRegisteredResourceValues(ctx context.Context, entityChainID string, action string, resourceValueRefs string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	var entities []*entity.Entity
	for _, entityID := range strings.Split(entityChainID, ",") {
		ent, ok := scenarioContext.GetObject(strings.TrimSpace(entityID)).(*entity.Entity)
		if !ok {
			return ctx, fmt.Errorf("entity %s not found or invalid type", entityID)
		}
		entities = append(entities, ent)
	}

	entityChain := &entity.EntityChain{Entities: entities}

	resources := make([]*authzV2.Resource, 0)
	resourceFQNMap := make(map[string]string)
	for idx, resourceValueRef := range strings.Split(resourceValueRefs, ",") {
		resourceValueFQN, err := resolveRegisteredResourceValueFQN(scenarioContext, resourceValueRef)
		if err != nil {
			return ctx, err
		}

		ephemeralID := fmt.Sprintf("rrv-%d", idx)
		resourceFQNMap[ephemeralID] = resourceValueFQN
		resources = append(resources, &authzV2.Resource{
			EphemeralId: ephemeralID,
			Resource: &authzV2.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: resourceValueFQN,
			},
		})
	}

	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{EntityChain: entityChain},
		},
		Action:                    &policy.Action{Name: strings.ToLower(action)},
		Resources:                 resources,
		FulfillableObligationFqns: getAllObligationsFromScenario(scenarioContext),
	}

	resp, err := scenarioContext.SDK.AuthorizationV2.GetDecisionMultiResource(ctx, req)
	scenarioContext.SetError(err)
	if err != nil {
		return ctx, err
	}

	scenarioContext.RecordObject(multiDecisionResponseKey, resp)
	scenarioContext.RecordObject(decisionResponse, resp)
	scenarioContext.RecordObject("resourceFQNMap", resourceFQNMap)
	return ctx, nil
}

func (s *RegisteredResourcesStepDefinitions) theMultiResourceDecisionShouldBe(ctx context.Context, expectedDecision string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	resp, ok := scenarioContext.GetObject(multiDecisionResponseKey).(*authzV2.GetDecisionMultiResourceResponse)
	if !ok || resp == nil {
		return ctx, errors.New("multi-decision response not found or invalid")
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

func RegisterRegisteredResourcesStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := &RegisteredResourcesStepDefinitions{}
	ctx.Step(`^I send a request to create a registered resource with:$`, stepDefinitions.iSendARequestToCreateARegisteredResourceWith)
	ctx.Step(`^I send a request to create a registered resource value with:$`, stepDefinitions.iSendARequestToCreateARegisteredResourceValueWith)
	ctx.Step(`^I send a decision request for entity chain "([^"]*)" for "([^"]*)" action on registered resource value "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForEntityChainForActionOnRegisteredResourceValue)
	ctx.Step(`^I send a decision request for registered resource value entity "([^"]*)" for "([^"]*)" action on resource "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForRegisteredResourceValueEntityForActionOnResource)
	ctx.Step(`^I send a decision request for registered resource value entity "([^"]*)" for "([^"]*)" action on registered resource value "([^"]*)"$`, stepDefinitions.iSendADecisionRequestForRegisteredResourceValueEntityForActionOnRegisteredResourceValue)
	ctx.Step(`^I send a multi-resource decision request for entity chain "([^"]*)" for "([^"]*)" action on registered resource values "([^"]*)"$`, stepDefinitions.iSendAMultiResourceDecisionRequestForEntityChainForActionOnRegisteredResourceValues)
	ctx.Step(`^the multi-resource decision should be "([^"]*)"$`, stepDefinitions.theMultiResourceDecisionShouldBe)
}
