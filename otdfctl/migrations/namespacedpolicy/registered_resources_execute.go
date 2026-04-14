package namespacedpolicy

import (
	"context"
	"fmt"
)

func (e *Executor) executeRegisteredResources(_ context.Context, plans []*RegisteredResourcePlan) error {
	if len(plans) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeRegisteredResources)
}
