package namespacedpolicy

import (
	"context"
	"fmt"
)

type (
	pruneDeleteFunc[T prunePlanItem] func(context.Context, T, string) error
)

func (e *Executor) ExecutePrune(ctx context.Context, plan *PrunePlan) error {
	if err := e.validatePrunePlan(plan); err != nil {
		return err
	}

	switch plan.Scopes[0] {
	case ScopeObligationTriggers:
		return e.executePruneObligationTriggers(ctx, plan.ObligationTriggers)
	case ScopeSubjectMappings:
		return e.executePruneSubjectMappings(ctx, plan.SubjectMappings)
	case ScopeRegisteredResources:
		return e.executePruneRegisteredResources(ctx, plan.RegisteredResources)
	case ScopeSubjectConditionSets:
		return e.executePruneSubjectConditionSets(ctx, plan.SubjectConditionSets)
	case ScopeActions:
		return e.executePruneActions(ctx, plan.Actions)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidScope, plan.Scopes[0])
	}
}

func (e *Executor) validatePrunePlan(plan *PrunePlan) error {
	if e == nil || e.handler == nil {
		return ErrNilExecutorHandler
	}
	if plan == nil {
		return ErrNilExecutionPlan
	}
	if len(plan.Scopes) == 0 {
		return ErrEmptyPlannerScope
	}
	if len(plan.Scopes) != 1 {
		return ErrMultiplePruneScopes
	}

	return nil
}

func (e *Executor) executePruneActions(ctx context.Context, plans []*PruneActionPlan) error {
	return executePruneItems(ctx, e, plans, "action", func(ctx context.Context, _ *PruneActionPlan, sourceID string) error {
		return e.handler.DeleteAction(ctx, sourceID)
	})
}

func (e *Executor) executePruneSubjectConditionSets(ctx context.Context, plans []*PruneSubjectConditionSetPlan) error {
	return executePruneItems(ctx, e, plans, "subject condition set", func(ctx context.Context, _ *PruneSubjectConditionSetPlan, sourceID string) error {
		return e.handler.DeleteSubjectConditionSet(ctx, sourceID)
	})
}

func (e *Executor) executePruneSubjectMappings(ctx context.Context, plans []*PruneSubjectMappingPlan) error {
	return executePruneItems(ctx, e, plans, "subject mapping", func(ctx context.Context, _ *PruneSubjectMappingPlan, sourceID string) error {
		_, err := e.handler.DeleteSubjectMapping(ctx, sourceID)
		return err
	})
}

func (e *Executor) executePruneRegisteredResources(ctx context.Context, plans []*PruneRegisteredResourcePlan) error {
	return executePruneItems(ctx, e, plans, "registered resource", func(ctx context.Context, _ *PruneRegisteredResourcePlan, sourceID string) error {
		return e.handler.DeleteRegisteredResource(ctx, sourceID)
	})
}

func (e *Executor) executePruneObligationTriggers(ctx context.Context, plans []*PruneObligationTriggerPlan) error {
	return executePruneItems(ctx, e, plans, "obligation trigger", func(ctx context.Context, _ *PruneObligationTriggerPlan, sourceID string) error {
		_, err := e.handler.DeleteObligationTrigger(ctx, sourceID)
		return err
	})
}

func executePruneItems[T prunePlanItem](
	ctx context.Context,
	executor *Executor,
	items []T,
	kind string,
	deleteSource pruneDeleteFunc[T],
) error {
	for _, item := range items {
		if item.status() != PruneStatusDelete {
			continue
		}

		id := item.sourceID()
		if id == "" {
			return executor.recordPruneFailure(item, fmt.Errorf("%w: %s", ErrMissingPruneSourceID, kind))
		}

		if err := deleteSource(ctx, item, id); err != nil {
			return executor.recordPruneFailure(item, fmt.Errorf("delete %s %q: %w", kind, id, err))
		}

		item.setExecution(&ExecutionResult{
			RunID:   executor.runID,
			Applied: true,
		})
	}

	return nil
}

func (e *Executor) recordPruneFailure(item prunePlanItem, err error) error {
	item.setExecution(&ExecutionResult{
		RunID:   e.runID,
		Failure: err.Error(),
	})
	return err
}
