package cukes

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
)

func RegisterResourceMappingScaleSteps(ctx *godog.ScenarioContext) {
	ctx.Step(`^I create (\d+) resource mappings for attribute "([^"]*)" in namespace "([^"]*)"$`, createScaleResourceMappings)
}

func createScaleResourceMappings(ctx context.Context, count int, attributeRef, namespaceRef string) (context.Context, error) {
	scenario, attribute, namespace, err := scaleMappingInputs(ctx, count, attributeRef, namespaceRef)
	if err != nil {
		return ctx, err
	}
	err = createScaleMappings(ctx, count, func(ctx context.Context, index int) error {
		response, err := scenario.SDK.ResourceMapping.CreateResourceMapping(ctx, &resourcemapping.CreateResourceMappingRequest{
			AttributeValueId: attribute.GetValues()[index].GetId(), NamespaceId: namespace,
			Terms: []string{fmt.Sprintf("resource-%04d", index)},
		})
		if err != nil {
			return fmt.Errorf("create resource mapping %d: %w", index, err)
		}
		if response.GetResourceMapping().GetId() == "" {
			return fmt.Errorf("resource mapping %d returned no identity", index)
		}
		return nil
	})
	return ctx, err
}
