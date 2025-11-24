package cukes

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

type SubjectMappingsStepDefinitions struct{}

func (s *SubjectMappingsStepDefinitions) iSendARequestToCreateSubjectMapping(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	cellIndexMap := make(map[int]string)
	subjectMappingRequests := []*subjectmapping.CreateSubjectMappingRequest{}
	referenceIDs := []string{}
	for ri, r := range tbl.Rows {
		subjectMappingRequest := subjectmapping.CreateSubjectMappingRequest{}
		subjectMappingRequest.Actions = []*policy.Action{}
		var standardActions *string
		var customActions *string
		for ci, c := range r.Cells {
			if ri == 0 {
				cellIndexMap[ci] = c.Value
			} else {
				switch cellIndexMap[ci] {
				case "attribute_value":
					av, err := scenarioContext.GetAttributeValue(ctx, strings.TrimSpace(c.Value))
					if err != nil {
						return nil, err
					}
					subjectMappingRequest.AttributeValueId = av.GetId()
				case "condition_set_name":
					scs, ok := scenarioContext.GetObject(strings.TrimSpace(c.Value)).(*policy.SubjectConditionSet)
					if !ok {
						return nil, fmt.Errorf("unable to get condition set for %s", c.Value)
					}
					subjectMappingRequest.ExistingSubjectConditionSetId = scs.GetId()
				case "standard actions":
					standardActions = &c.Value
				case "custom actions":
					customActions = &c.Value
				case "reference_id":
					referenceIDs = append(referenceIDs, strings.TrimSpace(c.Value))
				default:
					return ctx, fmt.Errorf("invalid condition value: %s", c.Value)
				}
			}
		}
		if ri > 0 {
			subjectMappingRequest.Actions = GetActionsFromValues(standardActions, customActions)
			subjectMappingRequests = append(subjectMappingRequests, &subjectMappingRequest)
		}
	}
	for i, subjectMappingRequest := range subjectMappingRequests {
		resp, err := scenarioContext.SDK.SubjectMapping.CreateSubjectMapping(ctx, subjectMappingRequest)
		if err != nil {
			return ctx, err
		}
		if resp != nil {
			scenarioContext.RecordObject(referenceIDs[i], resp.GetSubjectMapping())
		}
	}

	return ctx, nil
}

func (s *SubjectMappingsStepDefinitions) iSendARequestToCreateSubjectConditionSet(ctx context.Context, referenceID string, subjectSetIDs string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	subjectSets := []*policy.SubjectSet{}
	for _, subjectSetID := range strings.Split(subjectSetIDs, ",") {
		ss, ok := scenarioContext.GetObject(strings.TrimSpace(subjectSetID)).(*policy.SubjectSet)
		if !ok {
			return ctx, fmt.Errorf("invalid subject set id: %s", subjectSetID)
		}
		subjectSets = append(subjectSets, ss)
	}
	resp, respErr := scenarioContext.SDK.SubjectMapping.CreateSubjectConditionSet(ctx, &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
			SubjectSets: subjectSets,
		},
	})
	if resp != nil {
		scenarioContext.RecordObject(referenceID, resp.GetSubjectConditionSet())
	}
	scenarioContext.SetError(respErr)
	return ctx, nil
}

func (s *SubjectMappingsStepDefinitions) aSubjectSet(ctx context.Context, referenceID string, conditionGroupIDs string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	conditionGroups := []*policy.ConditionGroup{}
	for _, id := range strings.Split(conditionGroupIDs, ",") {
		id = strings.TrimSpace(id)
		cg, ok := scenarioContext.GetObject(id).(*policy.ConditionGroup)
		if !ok {
			return ctx, fmt.Errorf("invalid condition group id: %s", id)
		}
		conditionGroups = append(conditionGroups, cg)
	}
	subjectSet := &policy.SubjectSet{
		ConditionGroups: conditionGroups,
	}
	scenarioContext.RecordObject(referenceID, subjectSet)
	return ctx, nil
}

func (s *SubjectMappingsStepDefinitions) aConditionGroup(ctx context.Context, referenceID string, operator string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cellIndexMap := make(map[int]string)
	conditions := []*policy.Condition{}
	for ri, r := range tbl.Rows {
		condition := policy.Condition{}
		for ci, c := range r.Cells {
			if ri == 0 {
				cellIndexMap[ci] = c.Value
			} else {
				switch cellIndexMap[ci] {
				case "selector_value":
					condition.SubjectExternalSelectorValue = c.Value
				case "operator":
					condition.Operator = policy.SubjectMappingOperatorEnum(policy.SubjectMappingOperatorEnum_value["SUBJECT_MAPPING_OPERATOR_ENUM_"+strings.ToUpper(strings.TrimSpace(c.Value))])
				case "values":
					values := strings.Split(c.Value, ",")
					valueList := []string{}
					for _, value := range values {
						valueList = append(valueList, strings.TrimSpace(value))
					}
					condition.SubjectExternalValues = valueList
				}
			}
		}
		if ri > 0 {
			conditions = append(conditions, &condition)
		}
	}
	var boper policy.ConditionBooleanTypeEnum
	switch operator {
	case "or":
		boper = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR
	case "and":
		boper = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND
	}
	conditionGroup := &policy.ConditionGroup{
		BooleanOperator: boper,
		Conditions:      conditions,
	}
	scenarioContext.RecordObject(referenceID, conditionGroup)
	return ctx, nil
}

func RegisterSubjectMappingsStepsDefinitions(ctx *godog.ScenarioContext) {
	subjectMappingStepDefinitions := &SubjectMappingsStepDefinitions{}
	ctx.Step(`a condition group referenced as "([^"]*)" with an "([^"]*)" operator with conditions:$`, subjectMappingStepDefinitions.aConditionGroup)
	ctx.Step(`^a subject set referenced as "([^"]*)" containing the condition groups "([^"]*)"$`, subjectMappingStepDefinitions.aSubjectSet)
	ctx.Step(`^I send a request to create a subject condition set referenced as "([^"]*)" containing subject sets "([^"]*)"$`, subjectMappingStepDefinitions.iSendARequestToCreateSubjectConditionSet)
	ctx.Step(`^I send a request to create a subject mapping with:$`, subjectMappingStepDefinitions.iSendARequestToCreateSubjectMapping)
}
