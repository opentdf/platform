package namespacedpolicy

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

func (e *Executor) rememberSubjectConditionSetTarget(sourceID string, target *SubjectConditionSetTargetPlan) {
	if e == nil || sourceID == "" || target == nil {
		return
	}

	namespaceKey := namespaceRefKey(target.Namespace)
	if namespaceKey == "" {
		return
	}

	if e.subjectConditionSets == nil {
		e.subjectConditionSets = make(map[string]map[string]*SubjectConditionSetTargetPlan)
	}
	if e.subjectConditionSets[sourceID] == nil {
		e.subjectConditionSets[sourceID] = make(map[string]*SubjectConditionSetTargetPlan)
	}

	e.subjectConditionSets[sourceID][namespaceKey] = target
}

func (e *Executor) cachedScsTargetID(sourceID string, namespace *policy.Namespace) string {
	if e == nil || sourceID == "" {
		return ""
	}

	namespaceKey := namespaceRefKey(namespace)
	if namespaceKey == "" {
		return ""
	}

	targets := e.subjectConditionSets[sourceID]
	if targets == nil {
		return ""
	}

	target := targets[namespaceKey]
	if target == nil {
		return ""
	}

	return target.TargetID()
}

func (e *Executor) executeSubjectConditionSets(ctx context.Context, plans []*SubjectConditionSetPlan) error {
	if len(plans) == 0 {
		return nil
	}

	for _, scsPlan := range plans {
		if scsPlan == nil || scsPlan.Source == nil {
			continue
		}

		for _, target := range scsPlan.Targets {
			if target == nil {
				continue
			}

			if err := e.executeSubjectConditionSetTarget(ctx, scsPlan, target); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *Executor) executeSubjectConditionSetTarget(ctx context.Context, scsPlan *SubjectConditionSetPlan, target *SubjectConditionSetTargetPlan) error {
	//nolint:exhaustive // SCS execution only handles create and already-migrated explicitly; all other statuses are unsupported.
	switch target.Status {
	case TargetStatusAlreadyMigrated:
		if target.TargetID() == "" {
			return fmt.Errorf("%w: subject condition set %q target %q", ErrMissingMigratedTarget, scsPlan.Source.GetId(), namespaceLabel(target.Namespace))
		}
		e.rememberSubjectConditionSetTarget(scsPlan.Source.GetId(), target)
		return nil
	case TargetStatusSkipped:
		return nil
	case TargetStatusCreate:
		return e.createSubjectConditionSetTarget(ctx, scsPlan, target)
	case TargetStatusUnresolved:
		return nil
	default:
		return fmt.Errorf("%w: subject condition set %q target %q has unsupported status %q", ErrUnsupportedStatus, scsPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Status)
	}
}

func (e *Executor) createSubjectConditionSetTarget(ctx context.Context, scsPlan *SubjectConditionSetPlan, target *SubjectConditionSetTargetPlan) error {
	namespace := namespaceIdentifier(target.Namespace)
	if namespace == "" {
		return fmt.Errorf("%w: subject condition set %q", ErrTargetNamespaceRequired, scsPlan.Source.GetId())
	}

	created, err := e.handler.CreateSubjectConditionSet(
		ctx,
		scsPlan.Source.GetSubjectSets(),
		metadataForCreate(
			scsPlan.Source.GetId(),
			metadataLabels(scsPlan.Source.GetMetadata()),
			e.runID,
		),
		namespace,
	)
	if err != nil {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("create subject condition set %q in namespace %q: %w", scsPlan.Source.GetId(), namespaceLabel(target.Namespace), err)
	}
	if created.GetId() == "" {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: subject condition set %q target %q", ErrMissingCreatedTargetID, scsPlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	target.Execution = &ExecutionResult{
		RunID:           e.runID,
		Applied:         true,
		CreatedTargetID: created.GetId(),
	}
	e.rememberSubjectConditionSetTarget(scsPlan.Source.GetId(), target)

	return nil
}
