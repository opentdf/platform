package namespacedpolicy

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

func (e *Executor) executeSubjectMappings(ctx context.Context, plans []*SubjectMappingPlan) error {
	if len(plans) == 0 {
		return nil
	}

	for _, mappingPlan := range plans {
		if mappingPlan == nil || mappingPlan.Source == nil {
			continue
		}

		if mappingPlan.Target == nil {
			continue
		}

		if err := e.executeSubjectMappingTarget(ctx, mappingPlan, mappingPlan.Target); err != nil {
			return err
		}
	}

	return nil
}

func (e *Executor) executeSubjectMappingTarget(ctx context.Context, mappingPlan *SubjectMappingPlan, target *SubjectMappingTargetPlan) error {
	//nolint:exhaustive // Subject mapping execution only handles create and already-migrated explicitly; all other statuses are unsupported.
	switch target.Status {
	case TargetStatusAlreadyMigrated:
		if target.TargetID() == "" {
			return fmt.Errorf("%w: subject mapping %q target %q", ErrMissingMigratedTarget, mappingPlan.Source.GetId(), namespaceLabel(target.Namespace))
		}
		return nil
	case TargetStatusCreate:
		return e.createSubjectMappingTarget(ctx, mappingPlan, target)
	case TargetStatusUnresolved:
		return fmt.Errorf("%w: subject mapping %q target %q is unresolved: %s", ErrPlanNotExecutable, mappingPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Reason)
	default:
		return fmt.Errorf("%w: subject mapping %q target %q has unsupported status %q", ErrUnsupportedStatus, mappingPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Status)
	}
}

func (e *Executor) createSubjectMappingTarget(ctx context.Context, mappingPlan *SubjectMappingPlan, target *SubjectMappingTargetPlan) error {
	namespace := namespaceIdentifier(target.Namespace)
	if namespace == "" {
		return fmt.Errorf("%w: subject mapping %q", ErrTargetNamespaceRequired, mappingPlan.Source.GetId())
	}

	actions, err := e.resolveSubjectMappingActions(mappingPlan, target)
	if err != nil {
		return err
	}

	subjectConditionSetID, err := e.resolveSubjectMappingSubjectConditionSet(mappingPlan, target)
	if err != nil {
		return err
	}

	attributeValueID := mappingPlan.Source.GetAttributeValue().GetId()
	if attributeValueID == "" {
		return fmt.Errorf("subject mapping %q missing attribute value id", mappingPlan.Source.GetId())
	}

	created, err := e.handler.CreateNewSubjectMapping(
		ctx,
		attributeValueID,
		actions,
		subjectConditionSetID,
		nil,
		metadataForCreate(
			mappingPlan.Source.GetId(),
			metadataLabels(mappingPlan.Source.GetMetadata()),
			e.runID,
		),
		namespace,
	)
	if err != nil {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("create subject mapping %q in namespace %q: %w", mappingPlan.Source.GetId(), namespaceLabel(target.Namespace), err)
	}
	if created.GetId() == "" {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: subject mapping %q target %q", ErrMissingCreatedTargetID, mappingPlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	target.Execution = &ExecutionResult{
		RunID:           e.runID,
		Applied:         true,
		CreatedTargetID: created.GetId(),
	}

	return nil
}

func (e *Executor) resolveSubjectMappingActions(mappingPlan *SubjectMappingPlan, target *SubjectMappingTargetPlan) ([]*policy.Action, error) {
	actions := make([]*policy.Action, 0, len(target.ActionSourceIDs))
	for _, sourceID := range target.ActionSourceIDs {
		if sourceID == "" {
			return nil, fmt.Errorf("%w: subject mapping %q target %q", ErrMissingActionTarget, mappingPlan.Source.GetId(), namespaceLabel(target.Namespace))
		}

		targetID := e.cachedActionTargetID(sourceID, target.Namespace)
		if targetID == "" {
			return nil, fmt.Errorf("%w: subject mapping %q action %q target %q", ErrMissingActionTarget, mappingPlan.Source.GetId(), sourceID, namespaceLabel(target.Namespace))
		}

		actions = append(actions, &policy.Action{Id: targetID})
	}

	return actions, nil
}

func (e *Executor) resolveSubjectMappingSubjectConditionSet(mappingPlan *SubjectMappingPlan, target *SubjectMappingTargetPlan) (string, error) {
	if target.SubjectConditionSetSourceID == "" {
		return "", fmt.Errorf("%w: subject mapping %q target %q", ErrMissingSubjectConditionSetTarget, mappingPlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	targetID := e.cachedScsTargetID(target.SubjectConditionSetSourceID, target.Namespace)
	if targetID == "" {
		return "", fmt.Errorf("%w: subject mapping %q subject condition set %q target %q", ErrMissingSubjectConditionSetTarget, mappingPlan.Source.GetId(), target.SubjectConditionSetSourceID, namespaceLabel(target.Namespace))
	}

	return targetID, nil
}
