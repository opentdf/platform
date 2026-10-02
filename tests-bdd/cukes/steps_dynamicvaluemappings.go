package cukes

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
)

type DynamicValueMappingsStepDefinitions struct{}

// iSendARequestToCreateDynamicValueMapping creates one dynamic value mapping per data row via the
// SDK. Supported columns: attribute_definition_fqn, selector, operator (IN|IN_CONTAINS),
// standard actions, custom actions, condition_set_name (optional static pre-gate), reference_id.
func (s *DynamicValueMappingsStepDefinitions) iSendARequestToCreateDynamicValueMapping(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	cellIndexMap := make(map[int]string)
	requests := []*dynamicvaluemapping.CreateDynamicValueMappingRequest{}
	referenceIDs := []string{}

	for ri, r := range tbl.Rows {
		req := &dynamicvaluemapping.CreateDynamicValueMappingRequest{}
		resolver := &policy.DynamicValueResolver{}
		var standardActions *string
		var customActions *string
		referenceID := ""
		for ci, c := range r.Cells {
			if ri == 0 {
				cellIndexMap[ci] = c.Value
				continue
			}
			value := strings.TrimSpace(c.Value)
			switch cellIndexMap[ci] {
			case "attribute_definition_fqn":
				req.AttributeDefinitionFqn = value
			case "selector":
				resolver.SubjectExternalSelectorValue = value
			case "operator":
				op, ok := policy.SubjectMappingOperatorEnum_value["SUBJECT_MAPPING_OPERATOR_ENUM_"+strings.ToUpper(value)]
				if !ok {
					return ctx, fmt.Errorf("invalid dynamic value resolver operator: %s", value)
				}
				resolver.Operator = policy.SubjectMappingOperatorEnum(op)
			case "condition_set_name":
				scs, ok := scenarioContext.GetObject(value).(*policy.SubjectConditionSet)
				if !ok {
					return ctx, fmt.Errorf("unable to get condition set for %s", value)
				}
				req.ExistingSubjectConditionSetId = scs.GetId()
			case "standard actions":
				standardActions = &c.Value
			case "custom actions":
				customActions = &c.Value
			case "reference_id":
				referenceID = value
			default:
				return ctx, fmt.Errorf("invalid dynamic value mapping column: %s", cellIndexMap[ci])
			}
		}
		if ri > 0 {
			req.ValueResolver = resolver
			req.Actions = GetActionsFromValues(standardActions, customActions)
			requests = append(requests, req)
			referenceIDs = append(referenceIDs, referenceID)
		}
	}

	for i, req := range requests {
		resp, err := scenarioContext.SDK.DynamicValueMapping.CreateDynamicValueMapping(ctx, req)
		scenarioContext.SetError(err)
		if err != nil {
			return ctx, err
		}
		if resp != nil && referenceIDs[i] != "" {
			scenarioContext.RecordObject(referenceIDs[i], resp.GetDynamicValueMapping())
		}
	}

	return ctx, nil
}

func RegisterDynamicValueMappingsStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := &DynamicValueMappingsStepDefinitions{}
	ctx.Step(`^I send a request to create a dynamic value mapping with:$`, stepDefinitions.iSendARequestToCreateDynamicValueMapping)
}
