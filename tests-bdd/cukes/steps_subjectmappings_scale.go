package cukes

import (
	"context"
	"fmt"
	"slices"
	"strings"

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
	create := func(ctx context.Context, index int) error {
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
		if err := validateScaleMappingActions(response.GetSubjectMapping().GetActions(), action); err != nil {
			return fmt.Errorf("subject mapping %d: %w", index, err)
		}
		return nil
	}
	// Resolve any new action names before concurrent mapping creation starts.
	// Concurrent create-or-list calls can otherwise return an incomplete action set.
	if err := create(ctx, 0); err != nil {
		return ctx, err
	}
	err := createScaleMappings(ctx, count-1, func(ctx context.Context, index int) error {
		return create(ctx, index+1)
	})
	return ctx, err
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
