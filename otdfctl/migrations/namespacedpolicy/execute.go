package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
)

var (
	ErrNilExecutorHandler           = errors.New("executor handler is required")
	ErrNilExecutionPlan             = errors.New("execution plan is required")
	ErrPlanNotExecutable            = errors.New("plan is not executable")
	ErrExecutionPhaseNotImplemented = errors.New("execution phase is not implemented")
	ErrActionMissingExistingTarget  = errors.New("action target is missing an existing standard target id")
	ErrActionMissingMigratedTarget  = errors.New("action target is missing an already-migrated target id")
	ErrActionMissingTargetNamespace = errors.New("action target namespace is not set")
	ErrActionMissingCreatedTargetID = errors.New("create action returned no target id")
	ErrActionUnsupportedStatus      = errors.New("action target has unsupported status")
)

const (
	migrationLabelMigratedFrom = "migrated_from"
	migrationLabelRun          = "migration_run"
)

type ExecutorHandler interface {
	CreateAction(ctx context.Context, name string, namespace string, metadata *common.MetadataMutable) (*policy.Action, error)
}

type Executor struct {
	handler   ExecutorHandler
	runID     string
	actionIDs map[string]map[string]string
}

func NewExecutor(handler ExecutorHandler) (*Executor, error) {
	if handler == nil {
		return nil, ErrNilExecutorHandler
	}

	return &Executor{
		handler:   handler,
		runID:     uuid.NewString(),
		actionIDs: make(map[string]map[string]string),
	}, nil
}

func (e *Executor) Execute(ctx context.Context, plan *Plan) error {
	if err := e.validatePlan(plan); err != nil {
		return err
	}

	if err := e.executeActions(ctx, plan.Actions); err != nil {
		return err
	}
	if err := e.executeSubjectConditionSets(ctx, plan); err != nil {
		return err
	}
	if err := e.executeSubjectMappings(ctx, plan); err != nil {
		return err
	}
	if err := e.executeRegisteredResources(ctx, plan); err != nil {
		return err
	}
	if err := e.executeObligationTriggers(ctx, plan); err != nil {
		return err
	}

	return nil
}

func (e *Executor) validatePlan(plan *Plan) error {
	if e == nil || e.handler == nil {
		return ErrNilExecutorHandler
	}
	if plan == nil {
		return ErrNilExecutionPlan
	}
	if plan.Unresolved != nil && hasUnresolved(*plan.Unresolved) {
		return fmt.Errorf("%w: finalized plan contains unresolved entries", ErrPlanNotExecutable)
	}

	return nil
}

func metadataForCreate(sourceID string, sourceLabels map[string]string, runID string) *common.MetadataMutable {
	labels := map[string]string{}
	for key, value := range sourceLabels {
		labels[key] = value
	}

	labels[migrationLabelMigratedFrom] = sourceID
	labels[migrationLabelRun] = runID

	return &common.MetadataMutable{
		Labels: labels,
	}
}

func namespaceIdentifier(namespace *policy.Namespace) string {
	if namespace == nil {
		return ""
	}
	if id := strings.TrimSpace(namespace.GetId()); id != "" {
		return id
	}
	return strings.TrimSpace(namespace.GetFqn())
}

func namespaceLabel(namespace *policy.Namespace) string {
	if namespace == nil {
		return "<unknown>"
	}
	if id := strings.TrimSpace(namespace.GetId()); id != "" {
		return id
	}
	if fqn := strings.TrimSpace(namespace.GetFqn()); fqn != "" {
		return fqn
	}
	return "<unknown>"
}

func (e *Executor) setActionTargetID(sourceID string, namespace *policy.Namespace, targetID string) {
	if e == nil || sourceID == "" || targetID == "" {
		return
	}

	namespaceKey := namespaceRefKey(namespace)
	if namespaceKey == "" {
		return
	}

	if e.actionIDs == nil {
		e.actionIDs = make(map[string]map[string]string)
	}
	if e.actionIDs[sourceID] == nil {
		e.actionIDs[sourceID] = make(map[string]string)
	}

	e.actionIDs[sourceID][namespaceKey] = targetID
}

func (e *Executor) actionTargetID(sourceID string, namespace *policy.Namespace) string {
	if e == nil || sourceID == "" {
		return ""
	}

	namespaceKey := namespaceRefKey(namespace)
	if namespaceKey == "" {
		return ""
	}

	return e.actionIDs[sourceID][namespaceKey]
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

			switch target.Status {
			case TargetStatusExistingStandard:
				if target.TargetID() == "" {
					return fmt.Errorf("%w: action %q target %q", ErrActionMissingExistingTarget, actionPlan.Source.GetId(), namespaceLabel(target.Namespace))
				}
				e.setActionTargetID(actionPlan.Source.GetId(), target.Namespace, target.TargetID())
			case TargetStatusAlreadyMigrated:
				if target.TargetID() == "" {
					return fmt.Errorf("%w: action %q target %q", ErrActionMissingMigratedTarget, actionPlan.Source.GetId(), namespaceLabel(target.Namespace))
				}
				e.setActionTargetID(actionPlan.Source.GetId(), target.Namespace, target.TargetID())
				continue
			case TargetStatusCreate:
				namespace := namespaceIdentifier(target.Namespace)
				if namespace == "" {
					return fmt.Errorf("%w: action %q", ErrActionMissingTargetNamespace, actionPlan.Source.GetId())
				}

				created, err := e.handler.CreateAction(
					ctx,
					actionPlan.Source.GetName(),
					namespace,
					metadataForCreate(
						actionPlan.Source.GetId(),
						actionPlan.Source.GetMetadata().GetLabels(),
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
				if created == nil || created.GetId() == "" {
					target.Execution = &ExecutionResult{
						RunID:   e.runID,
						Failure: ErrActionMissingCreatedTargetID.Error(),
					}
					return fmt.Errorf("%w: action %q target %q", ErrActionMissingCreatedTargetID, actionPlan.Source.GetId(), namespaceLabel(target.Namespace))
				}

				target.Execution = &ExecutionResult{
					RunID:           e.runID,
					Applied:         true,
					CreatedTargetID: created.GetId(),
				}
				e.setActionTargetID(actionPlan.Source.GetId(), target.Namespace, created.GetId())
			case TargetStatusUnresolved:
				// ! Note: This should never really happen, as the validatePlan should be run before this; good defensive check though.
				return fmt.Errorf("%w: action %q target %q is unresolved: %s", ErrPlanNotExecutable, actionPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Reason)
			default:
				return fmt.Errorf("%w: action %q target %q has unsupported status %q", ErrActionUnsupportedStatus, actionPlan.Source.GetId(), namespaceLabel(target.Namespace), target.Status)
			}
		}
	}

	return nil
}

func (e *Executor) executeSubjectConditionSets(_ context.Context, plan *Plan) error {
	if plan == nil || len(plan.SubjectConditionSets) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeSubjectConditionSets)
}

func (e *Executor) executeSubjectMappings(_ context.Context, plan *Plan) error {
	if plan == nil || len(plan.SubjectMappings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeSubjectMappings)
}

func (e *Executor) executeRegisteredResources(_ context.Context, plan *Plan) error {
	if plan == nil || len(plan.RegisteredResources) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeRegisteredResources)
}

func (e *Executor) executeObligationTriggers(_ context.Context, plan *Plan) error {
	if plan == nil || len(plan.ObligationTriggers) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrExecutionPhaseNotImplemented, ScopeObligationTriggers)
}
