package namespacedpolicy

import (
	"context"
	"fmt"
)

func (e *Executor) executeSubjectMappings(_ context.Context, plans []*SubjectMappingPlan) error {
	if len(plans) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeSubjectMappings)
}
