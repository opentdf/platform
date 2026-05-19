package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
)

type (
	pruneDeleteFunc[T prunePlanItem] func(context.Context, T, string) error
)

var (
	ErrNilPruneExecutionPlan = errors.New("prune plan is required")
	ErrMissingPruneSourceID  = errors.New("missing prune source id")
)

type PruneExecutor struct {
	handler ExecutorHandler
}

func NewPruneExecutor(handler ExecutorHandler) (*PruneExecutor, error) {
	if handler == nil {
		return nil, ErrNilExecutorHandler
	}

	return &PruneExecutor{handler: handler}, nil
}

func (e *PruneExecutor) ExecutePrune(ctx context.Context, plan *PrunePlan) error {
	if err := e.validatePrunePlan(plan); err != nil {
		return err
	}

	switch plan.Scope {
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
		return fmt.Errorf("%w: %s", ErrInvalidScope, plan.Scope)
	}
}

func (e *PruneExecutor) validatePrunePlan(plan *PrunePlan) error {
	if e == nil || e.handler == nil {
		return ErrNilExecutorHandler
	}
	if plan == nil {
		return ErrNilPruneExecutionPlan
	}
	if plan.Scope == "" {
		return ErrEmptyPlannerScope
	}

	return nil
}

func (e *PruneExecutor) executePruneActions(ctx context.Context, plans []*PruneActionPlan) error {
	return executePruneItems(ctx, e, plans, "action", func(ctx context.Context, _ *PruneActionPlan, sourceID string) error {
		return e.handler.DeleteAction(ctx, sourceID)
	})
}

func (e *PruneExecutor) executePruneSubjectConditionSets(ctx context.Context, plans []*PruneSubjectConditionSetPlan) error {
	return executePruneItems(ctx, e, plans, "subject condition set", func(ctx context.Context, _ *PruneSubjectConditionSetPlan, sourceID string) error {
		return e.handler.DeleteSubjectConditionSet(ctx, sourceID)
	})
}

func (e *PruneExecutor) executePruneSubjectMappings(ctx context.Context, plans []*PruneSubjectMappingPlan) error {
	return executePruneItems(ctx, e, plans, "subject mapping", func(ctx context.Context, _ *PruneSubjectMappingPlan, sourceID string) error {
		_, err := e.handler.DeleteSubjectMapping(ctx, sourceID)
		return err
	})
}

func (e *PruneExecutor) executePruneRegisteredResources(ctx context.Context, plans []*PruneRegisteredResourcePlan) error {
	return executePruneItems(ctx, e, plans, "registered resource", func(ctx context.Context, _ *PruneRegisteredResourcePlan, sourceID string) error {
		return e.handler.DeleteRegisteredResource(ctx, sourceID)
	})
}

func (e *PruneExecutor) executePruneObligationTriggers(ctx context.Context, plans []*PruneObligationTriggerPlan) error {
	return executePruneItems(ctx, e, plans, "obligation trigger", func(ctx context.Context, _ *PruneObligationTriggerPlan, sourceID string) error {
		_, err := e.handler.DeleteObligationTrigger(ctx, sourceID)
		return err
	})
}

func executePruneItems[T prunePlanItem](
	ctx context.Context,
	executor *PruneExecutor,
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
			Applied: true,
		})
	}

	return nil
}

func (e *PruneExecutor) recordPruneFailure(item prunePlanItem, err error) error {
	item.setExecution(&ExecutionResult{
		Failure: err.Error(),
	})
	return err
}
