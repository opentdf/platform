package cukes

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

// Each value has a distinct condition set, matching either a user's entitlement
// or an approved client. Sharing one condition set hides policy evaluation costs.
func scaleValueConditions(selector string, values []string) *subjectmapping.SubjectConditionSetCreate {
	return &subjectmapping.SubjectConditionSetCreate{SubjectSets: []*policy.SubjectSet{{
		ConditionGroups: []*policy.ConditionGroup{{
			BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
			Conditions: []*policy.Condition{
				{SubjectExternalSelectorValue: selector, Operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, SubjectExternalValues: values},
				{SubjectExternalSelectorValue: ".clientId", Operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, SubjectExternalValues: []string{"scale-browser", "scale-mail", "scale-gateway", "scale-cli"}},
			},
		}},
	}}}
}

func (s *SubjectMappingsStepDefinitions) createScaleSubjectMappings(ctx context.Context, count int, attributeRef, selector, action string) (context.Context, error) {
	scenario := GetPlatformScenarioContext(ctx)
	attribute, ok := scenario.GetObject(attributeRef).(*policy.Attribute)
	if !ok || count <= 0 || count > len(attribute.GetValues()) {
		return ctx, fmt.Errorf("attribute %q must contain at least %d values", attributeRef, count)
	}
	create := func(ctx context.Context, index int) error {
		value := attribute.GetValues()[index]
		response, err := scenario.SDK.SubjectMapping.CreateSubjectMapping(ctx, &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId:       value.GetId(),
			NewSubjectConditionSet: scaleValueConditions(selector, []string{value.GetValue(), "project-" + value.GetValue()}),
			Actions:                GetActionsFromValues(&action, nil),
		})
		if err != nil {
			return fmt.Errorf("create subject mapping %d: %w", index, err)
		}
		if response.GetSubjectMapping().GetId() == "" {
			return fmt.Errorf("subject mapping %d returned no identity", index)
		}
		return validateScaleMappingActions(response.GetSubjectMapping().GetActions(), action)
	}
	// Resolve new action names before concurrent mapping creation starts.
	if err := create(ctx, 0); err != nil {
		return ctx, err
	}
	return ctx, createScaleMappings(ctx, count-1, func(ctx context.Context, index int) error { return create(ctx, index+1) })
}

func validateScaleMappingActions(actions []*policy.Action, expected string) error {
	want := strings.Split(strings.ToLower(expected), ",")
	for i := range want {
		want[i] = strings.TrimSpace(want[i])
	}
	got := make([]string, len(actions))
	for i, action := range actions {
		got[i] = strings.ToLower(action.GetName())
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		return fmt.Errorf("expected actions %v, got %v", want, got)
	}
	return nil
}
