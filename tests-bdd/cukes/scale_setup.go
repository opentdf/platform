package cukes

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/opentdf/platform/protocol/go/policy"
)

// Setup uses bounded API calls and finishes before authorization is measured.
func createScaleMappings(ctx context.Context, count int, create func(context.Context, int) error) error {
	// Match the default HTTP idle pool so thousands of setup calls reuse connections.
	const batchSize = 2
	for start := 0; start < count; start += batchSize {
		end := min(start+batchSize, count)
		failures := make([]error, end-start)
		var workers sync.WaitGroup
		for index := start; index < end; index++ {
			workers.Go(func() { failures[index-start] = create(ctx, index) })
		}
		workers.Wait()
		if err := errors.Join(failures...); err != nil {
			return err
		}
	}
	return nil
}

func scaleMappingInputs(ctx context.Context, count int, attributeRef, namespaceRef string) (*PlatformScenarioContext, *policy.Attribute, string, error) {
	scenario := GetPlatformScenarioContext(ctx)
	attribute, ok := scenario.GetObject(attributeRef).(*policy.Attribute)
	if !ok || count <= 0 || count > len(attribute.GetValues()) {
		return nil, nil, "", fmt.Errorf("attribute %q must contain at least %d values for mapping setup", attributeRef, count)
	}
	namespace, ok := scenario.GetObject(namespaceRef).(string)
	if !ok {
		return nil, nil, "", fmt.Errorf("missing namespace %q", namespaceRef)
	}
	return scenario, attribute, namespace, nil
}
