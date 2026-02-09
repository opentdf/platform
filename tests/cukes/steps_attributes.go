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
				case "name":
					createAttributeRequest.Name = cell.Value
				case "rule":
					switch cell.Value {
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

func RegisterAttributeStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	stepDefinitions := AttributesStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^a (anyOf|allOf|hierarchy) attribute definition with values: "([^"]*)"$`, stepDefinitions.aAttributeDef)
	ctx.Step(`^I send a request to create an attribute with:$`, stepDefinitions.iSendARequestToCreateAnAttributeWith)
}
