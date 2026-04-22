package namespacedpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

func (e *Executor) executeObligationTriggers(ctx context.Context, plans []*ObligationTriggerPlan) error {
	if len(plans) == 0 {
		return nil
	}

	for _, triggerPlan := range plans {
		if triggerPlan == nil || triggerPlan.Source == nil {
			continue
		}

		if triggerPlan.Target == nil {
			continue
		}

		if err := e.executeObligationTriggerTarget(ctx, triggerPlan, triggerPlan.Target); err != nil {
			return err
		}
	}

	return nil
}

func (e *Executor) executeObligationTriggerTarget(ctx context.Context, triggerPlan *ObligationTriggerPlan, target *ObligationTriggerTargetPlan) error {
	//nolint:exhaustive // Obligation-trigger execution only handles create and already-migrated explicitly; all other statuses are unsupported.
	switch target.Status {
	case TargetStatusAlreadyMigrated:
		if target.TargetID() == "" {
			return fmt.Errorf("%w: obligation trigger %q target %q", ErrMissingMigratedTarget, triggerPlan.Source.GetId(), namespaceLabel(target.Namespace))
		}
		return nil
	case TargetStatusSkipped:
		return nil
	case TargetStatusCreate:
		return e.createObligationTriggerTarget(ctx, triggerPlan, target)
	case TargetStatusUnresolved:
		return fmt.Errorf("%w: obligation trigger %q target %q is unresolved: %s", ErrPlanNotExecutable, triggerPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Reason)
	default:
		return fmt.Errorf("%w: obligation trigger %q target %q has unsupported status %q", ErrUnsupportedStatus, triggerPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Status)
	}
}

func (e *Executor) createObligationTriggerTarget(ctx context.Context, triggerPlan *ObligationTriggerPlan, target *ObligationTriggerTargetPlan) error {
	actionID, err := e.requireActionTargetID(target.ActionSourceID, target.Namespace, triggerPlan.Source.GetId())
	if err != nil {
		return err
	}

	created, err := e.handler.CreateObligationTrigger(
		ctx,
		valueIDOrFQN(triggerPlan.Source.GetAttributeValue()),
		actionID,
		obligationValueIDOrFQN(triggerPlan.Source.GetObligationValue()),
		triggerClientID(triggerPlan.Source.GetContext()),
		metadataForCreate(
			triggerPlan.Source.GetId(),
			metadataLabels(triggerPlan.Source.GetMetadata()),
			e.runID,
		),
	)
	if err != nil {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("create obligation trigger %q in namespace %q: %w", triggerPlan.Source.GetId(), namespaceLabel(target.Namespace), err)
	}
	if created.GetId() == "" {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: obligation trigger %q target %q", ErrMissingCreatedTargetID, triggerPlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	target.Execution = &ExecutionResult{
		RunID:           e.runID,
		Applied:         true,
		CreatedTargetID: created.GetId(),
	}

	return nil
}

// TODO: Eventually make this generic when we merge sm / rr
func (e *Executor) requireActionTargetID(sourceID string, targetNamespace *policy.Namespace, ownerID string) (string, error) {
	if sourceID == "" {
		return "", fmt.Errorf("%w: obligation trigger %q action source id is missing", ErrMissingMigratedTarget, ownerID)
	}

	actionID := e.cachedActionTargetID(sourceID, targetNamespace)
	if actionID != "" {
		return actionID, nil
	}

	return "", fmt.Errorf("%w: obligation trigger %q action %q target %q", ErrMissingMigratedTarget, ownerID, sourceID, namespaceLabel(targetNamespace))
}

func valueIDOrFQN(value *policy.Value) string {
	if value == nil {
		return ""
	}
	if id := strings.TrimSpace(value.GetId()); id != "" {
		return id
	}
	return strings.TrimSpace(value.GetFqn())
}

func obligationValueIDOrFQN(value *policy.ObligationValue) string {
	if value == nil {
		return ""
	}
	if id := strings.TrimSpace(value.GetId()); id != "" {
		return id
	}
	return strings.TrimSpace(value.GetFqn())
}

func triggerClientID(contexts []*policy.RequestContext) string {
	for _, requestContext := range contexts {
		if requestContext == nil || requestContext.GetPep() == nil {
			continue
		}
		if clientID := strings.TrimSpace(requestContext.GetPep().GetClientId()); clientID != "" {
			return clientID
		}
	}

	return ""
}
