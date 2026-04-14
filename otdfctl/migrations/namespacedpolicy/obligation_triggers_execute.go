package namespacedpolicy

import (
	"context"
	"fmt"
)

func (e *Executor) executeObligationTriggers(_ context.Context, plans []*ObligationTriggerPlan) error {
	if len(plans) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeObligationTriggers)
}
