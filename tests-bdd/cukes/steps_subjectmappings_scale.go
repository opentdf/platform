package cukes

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

func (s *SubjectMappingsStepDefinitions) createScaleSubjectMappings(ctx context.Context, count int, attributeRef, conditionSetRef, action string) (context.Context, error) {
	scenario := GetPlatformScenarioContext(ctx)
	attribute, ok := scenario.GetObject(attributeRef).(*policy.Attribute)
	if !ok || count <= 0 || count > len(attribute.GetValues()) {
		return ctx, fmt.Errorf("attribute %q must contain at least %d values", attributeRef, count)
	}
	conditionSet, ok := scenario.GetObject(conditionSetRef).(*policy.SubjectConditionSet)
	if !ok {
		return ctx, fmt.Errorf("missing condition set %q", conditionSetRef)
	}
	err := createScaleMappings(ctx, count, func(ctx context.Context, index int) error {
		response, err := scenario.SDK.SubjectMapping.CreateSubjectMapping(ctx, &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId: attribute.GetValues()[index].GetId(), ExistingSubjectConditionSetId: conditionSet.GetId(),
			Actions: GetActionsFromValues(&action, nil),
		})
		if err != nil {
			return fmt.Errorf("create subject mapping %d: %w", index, err)
		}
		if response.GetSubjectMapping().GetId() == "" {
			return fmt.Errorf("subject mapping %d returned no identity", index)
		}
		return nil
	})
	return ctx, err
}
