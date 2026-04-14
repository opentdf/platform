package namespacedpolicy

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

func (e *Executor) rememberActionTarget(sourceID string, target *ActionTargetPlan) {
	if e == nil || sourceID == "" || target == nil {
		return
	}

	namespaceKey := namespaceRefKey(target.Namespace)
	if namespaceKey == "" {
		return
	}

	if e.actionTargets == nil {
		e.actionTargets = make(map[string]map[string]*ActionTargetPlan)
	}
	if e.actionTargets[sourceID] == nil {
		e.actionTargets[sourceID] = make(map[string]*ActionTargetPlan)
	}

	e.actionTargets[sourceID][namespaceKey] = target
}

func (e *Executor) cachedActionTargetID(sourceID string, namespace *policy.Namespace) string {
	if e == nil || sourceID == "" {
		return ""
	}

	namespaceKey := namespaceRefKey(namespace)
	if namespaceKey == "" {
		return ""
	}

	target := e.actionTargets[sourceID][namespaceKey]
	if target == nil {
		return ""
	}

	return target.TargetID()
}

func (e *Executor) executeActions(ctx context.Context, actionPlans []*ActionPlan) error {
	for _, actionPlan := range actionPlans {
		if actionPlan == nil || actionPlan.Source == nil {
			continue
		}

		for _, target := range actionPlan.Targets {
			if target == nil {
				continue
			}

			if err := e.executeActionTarget(ctx, actionPlan, target); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *Executor) executeActionTarget(ctx context.Context, actionPlan *ActionPlan, target *ActionTargetPlan) error {
	switch target.Status {
	case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
		if target.TargetID() == "" {
			errKind := ErrMissingExistingTarget
			if target.Status == TargetStatusAlreadyMigrated {
				errKind = ErrMissingMigratedTarget
			}
			return fmt.Errorf("%w: action %q target %q", errKind, actionPlan.Source.GetId(), namespaceLabel(target.Namespace))
		}
		e.rememberActionTarget(actionPlan.Source.GetId(), target)
		return nil
	case TargetStatusCreate:
		return e.createActionTarget(ctx, actionPlan, target)
	case TargetStatusUnresolved:
		return fmt.Errorf("%w: action %q target %q is unresolved: %s", ErrPlanNotExecutable, actionPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Reason)
	default:
		return fmt.Errorf("%w: action %q target %q has unsupported status %q", ErrUnsupportedStatus, actionPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Status)
	}
}

func (e *Executor) createActionTarget(ctx context.Context, actionPlan *ActionPlan, target *ActionTargetPlan) error {
	namespace := namespaceIdentifier(target.Namespace)
	if namespace == "" {
		return fmt.Errorf("%w: action %q", ErrTargetNamespaceRequired, actionPlan.Source.GetId())
	}

	created, err := e.handler.CreateAction(
		ctx,
		actionPlan.Source.GetName(),
		namespace,
		metadataForCreate(
			actionPlan.Source.GetId(),
			metadataLabels(actionPlan.Source.GetMetadata()),
			e.runID,
		),
	)
	if err != nil {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("create action %q in namespace %q: %w", actionPlan.Source.GetId(), namespaceLabel(target.Namespace), err)
	}
	if created.GetId() == "" {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: action %q target %q", ErrMissingCreatedTargetID, actionPlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	target.Execution = &ExecutionResult{
		RunID:           e.runID,
		Applied:         true,
		CreatedTargetID: created.GetId(),
	}
	e.rememberActionTarget(actionPlan.Source.GetId(), target)

	return nil
}
