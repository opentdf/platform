package cukes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

const (
	createAttributeResponseKey = "createAttributeResponse"
)

type AttributesStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
}

func (s *AttributesStepDefinitions) aAttributeDef(ctx context.Context, _ string, _ string) (context.Context, error) {
	return ctx, nil
}

func (s *AttributesStepDefinitions) iSendARequestToCreateAnAttributeWith(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	createAttrRequests, err := s.createAttributeRequestFromTable(scenarioContext, tbl)
	scenarioContext.ClearError()
	if err == nil {
		for _, req := range createAttrRequests {
			resp, respErr := scenarioContext.SDK.Attributes.CreateAttribute(ctx, req)
			scenarioContext.SetError(respErr)
			scenarioContext.RecordObject(createAttributeResponseKey, resp)
		}
	}
	return ctx, err
}

func (s *AttributesStepDefinitions) createAttributeRequestFromTable(scenarioContext *PlatformScenarioContext, tbl *godog.Table) ([]*attributes.CreateAttributeRequest, error) {
	cellMap := make(map[int]string)
	requests := []*attributes.CreateAttributeRequest{}
	for i, row := range tbl.Rows {
		if i == 0 {
			for c, cell := range row.Cells {
				cellMap[c] = cell.Value
			}
		} else {
			createAttributeRequest := attributes.CreateAttributeRequest{}
			for c, cell := range row.Cells {
				cellName := cellMap[c]
				switch cellName {
				case "namespace_id":
					id, ok := scenarioContext.GetObject(cell.Value).(string)
					if !ok {
						return nil, errors.New("unable to extract namespace ID")
					}
					createAttributeRequest.NamespaceId = id
				case nameKey:
					createAttributeRequest.Name = strings.TrimSpace(cell.Value)
				case "rule":
					switch strings.TrimSpace(cell.Value) {
					case "anyOf":
						createAttributeRequest.Rule = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF
					case "allOf":
						createAttributeRequest.Rule = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
					case "hierarchy":
						createAttributeRequest.Rule = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY
					default:
						return requests, fmt.Errorf("unknown attribute rule type %s", cell.Value)
					}
				case "values":
					values := []string{}
					for _, value := range strings.Split(cell.Value, ",") {
						values = append(values, strings.TrimSpace(value))
					}
					createAttributeRequest.Values = values
				default:
					return requests, fmt.Errorf("invalid table cell name: %s", cellName)
				}
			}
			requests = append(requests, &createAttributeRequest)
		}
	}
	return requests, nil
}

// iSendARequestToCreateAnAttributeWithGeneratedValues creates an attribute with valueCount
// programmatically-generated values (v0000, v0001, ...), too many to list inline. It records the
// created attribute under referenceID so a subject mapping can later be added for each value,
// reproducing the many-values shape of opentdf/platform#3821.
func (s *AttributesStepDefinitions) iSendARequestToCreateAnAttributeWithGeneratedValues(ctx context.Context, referenceID, namespaceRef, name, rule string, valueCount int) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	nsID, ok := scenarioContext.GetObject(strings.TrimSpace(namespaceRef)).(string)
	if !ok {
		return ctx, fmt.Errorf("unable to get namespace id for %s", namespaceRef)
	}

	var ruleType policy.AttributeRuleTypeEnum
	switch strings.TrimSpace(rule) {
	case "anyOf":
		ruleType = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF
	case "allOf":
		ruleType = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
	case "hierarchy":
		ruleType = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY
	default:
		return ctx, fmt.Errorf("unknown attribute rule type %s", rule)
	}

	values := make([]string, 0, valueCount)
	for i := range valueCount {
		values = append(values, fmt.Sprintf("v%04d", i))
	}

	resp, err := scenarioContext.SDK.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		NamespaceId: nsID,
		Name:        strings.TrimSpace(name),
		Rule:        ruleType,
		Values:      values,
	})
	if resp != nil {
		scenarioContext.RecordObject(strings.TrimSpace(referenceID), resp.GetAttribute())
	}
	scenarioContext.SetError(err)
	return ctx, nil
}

// iDeactivateTheAttributeValue resolves the value by FQN and deactivates it. A deactivated value
// must no longer entitle an entity nor be satisfiable on a resource, so decisions and KAS rewraps
// touching it must fail closed.
func (s *AttributesStepDefinitions) iDeactivateTheAttributeValue(ctx context.Context, fqn string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	value, err := scenarioContext.GetAttributeValue(ctx, strings.TrimSpace(fqn))
	if err != nil {
		return ctx, fmt.Errorf("resolve attribute value %s: %w", fqn, err)
	}

	_, err = scenarioContext.SDK.Attributes.DeactivateAttributeValue(ctx, &attributes.DeactivateAttributeValueRequest{
		Id: value.GetId(),
	})
	if err != nil {
		return ctx, fmt.Errorf("deactivate attribute value %s: %w", fqn, err)
	}
	return ctx, nil
}

// iDeactivateTheAttributeDefinition resolves the definition by FQN and deactivates it. Deactivating
// a definition does not cascade to its values in the database, so every decision path must deny on
// the definition's own state.
func (s *AttributesStepDefinitions) iDeactivateTheAttributeDefinition(ctx context.Context, fqn string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	trimmed := strings.TrimSpace(fqn)
	resp, err := scenarioContext.SDK.Attributes.GetAttribute(ctx, &attributes.GetAttributeRequest{
		Identifier: &attributes.GetAttributeRequest_Fqn{Fqn: trimmed},
	})
	if err != nil {
		return ctx, fmt.Errorf("resolve attribute definition %s: %w", fqn, err)
	}

	_, err = scenarioContext.SDK.Attributes.DeactivateAttribute(ctx, &attributes.DeactivateAttributeRequest{
		Id: resp.GetAttribute().GetId(),
	})
	if err != nil {
		return ctx, fmt.Errorf("deactivate attribute definition %s: %w", fqn, err)
	}
	return ctx, nil
}

func RegisterAttributeStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	stepDefinitions := AttributesStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^a (anyOf|allOf|hierarchy) attribute definition with values: "([^"]*)"$`, stepDefinitions.aAttributeDef)
	ctx.Step(`^I deactivate the attribute value "([^"]*)"$`, stepDefinitions.iDeactivateTheAttributeValue)
	ctx.Step(`^I deactivate the attribute definition "([^"]*)"$`, stepDefinitions.iDeactivateTheAttributeDefinition)
	ctx.Step(`^I send a request to create an attribute with:$`, stepDefinitions.iSendARequestToCreateAnAttributeWith)
	ctx.Step(`^I send a request to create an attribute referenced as "([^"]*)" in namespace "([^"]*)" named "([^"]*)" with rule "([^"]*)" and (\d+) generated values$`, stepDefinitions.iSendARequestToCreateAnAttributeWithGeneratedValues)
}
