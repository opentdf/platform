package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
)

func (e *Executor) executeRegisteredResources(ctx context.Context, plans []*RegisteredResourcePlan) error {
	if len(plans) == 0 {
		return nil
	}

	for _, plan := range plans {
		if plan == nil || plan.Source == nil {
			continue
		}

		if plan.Target == nil {
			continue
		}

		if err := e.executeRegisteredResourceTarget(ctx, plan, plan.Target); err != nil {
			return err
		}
	}

	return nil
}

func (e *Executor) executeRegisteredResourceTarget(ctx context.Context, plan *RegisteredResourcePlan, target *RegisteredResourceTargetPlan) error {
	switch target.Status {
	case TargetStatusAlreadyMigrated:
		if target.TargetID() == "" {
			return fmt.Errorf("%w: registered resource %q target %q", ErrMissingMigratedTarget, plan.Source.GetId(), namespaceLabel(target.Namespace))
		}
		return nil
	case TargetStatusSkipped:
		return nil
	case TargetStatusCreate:
		return e.createRegisteredResourceTarget(ctx, plan, target)
	case TargetStatusUnresolved:
		return nil
	default:
		return fmt.Errorf("%w: registered resource %q target %q has unsupported status %q", ErrUnsupportedStatus, plan.Source.GetId(), namespaceLabel(target.Namespace), target.Status)
	}
}

func (e *Executor) createRegisteredResourceTarget(ctx context.Context, plan *RegisteredResourcePlan, target *RegisteredResourceTargetPlan) error {
	namespace := namespaceIdentifier(target.Namespace)
	if namespace == "" {
		return fmt.Errorf("%w: registered resource %q", ErrTargetNamespaceRequired, plan.Source.GetId())
	}

	created, err := e.handler.CreateRegisteredResource(
		ctx,
		namespace,
		plan.Source.GetName(),
		nil,
		metadataForCreate(
			plan.Source.GetId(),
			metadataLabels(plan.Source.GetMetadata()),
			e.runID,
		),
	)
	if err != nil {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("%w: create registered resource %q in namespace %q", err, plan.Source.GetId(), namespaceLabel(target.Namespace))
	}
	if created == nil {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: registered resource %q target %q", ErrMissingCreatedTargetID, plan.Source.GetId(), namespaceLabel(target.Namespace))
	}
	if created.GetId() == "" {
		target.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: registered resource %q target %q", ErrMissingCreatedTargetID, plan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	target.Execution = &ExecutionResult{
		RunID:           e.runID,
		Applied:         true,
		CreatedTargetID: created.GetId(),
	}

	existingValues := registeredResourceValueIDsByValue(created)
	for _, valuePlan := range target.Values {
		if valuePlan == nil || valuePlan.Source == nil {
			continue
		}

		// RR values are reconciled at runtime so explicit parent reuse can skip
		// values that already exist on the chosen parent RR.
		if existingID := existingValues[registeredResourceValueKey(valuePlan.Source.GetValue())]; existingID != "" {
			valuePlan.Execution = &ExecutionResult{
				RunID:           e.runID,
				Applied:         true,
				CreatedTargetID: existingID,
			}
			continue
		}

		if err := e.createRegisteredResourceValue(ctx, target, valuePlan); err != nil {
			return err
		}
	}

	return nil
}

func (e *Executor) createRegisteredResourceValue(ctx context.Context, target *RegisteredResourceTargetPlan, valuePlan *RegisteredResourceValuePlan) error {
	actionAttributeValues, err := e.registeredResourceActionAttributeValues(target.Namespace, valuePlan)
	if err != nil {
		valuePlan.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("%w: build registered resource value %q action bindings for namespace %q", err, valuePlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	created, err := e.handler.CreateRegisteredResourceValue(
		ctx,
		target.TargetID(),
		valuePlan.Source.GetValue(),
		actionAttributeValues,
		metadataForCreate(
			valuePlan.Source.GetId(),
			metadataLabels(valuePlan.Source.GetMetadata()),
			e.runID,
		),
	)
	if err != nil {
		valuePlan.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: err.Error(),
		}
		return fmt.Errorf("%w: create registered resource value %q for resource %q in namespace %q", err, valuePlan.Source.GetId(), target.TargetID(), namespaceLabel(target.Namespace))
	}
	if created.GetId() == "" {
		valuePlan.Execution = &ExecutionResult{
			RunID:   e.runID,
			Failure: ErrMissingCreatedTargetID.Error(),
		}
		return fmt.Errorf("%w: registered resource value %q for target %q", ErrMissingCreatedTargetID, valuePlan.Source.GetId(), namespaceLabel(target.Namespace))
	}

	valuePlan.Execution = &ExecutionResult{
		RunID:           e.runID,
		Applied:         true,
		CreatedTargetID: created.GetId(),
	}

	return nil
}

func (e *Executor) registeredResourceActionAttributeValues(namespace *policy.Namespace, valuePlan *RegisteredResourceValuePlan) ([]*registeredresources.ActionAttributeValue, error) {
	if valuePlan == nil {
		return nil, nil
	}

	actionAttributeValues := make([]*registeredresources.ActionAttributeValue, 0, len(valuePlan.ActionBindings))
	for _, binding := range valuePlan.ActionBindings {
		if binding == nil {
			continue
		}

		if binding.SourceActionID == "" {
			return nil, fmt.Errorf("%w: action source id is missing", ErrPlanNotExecutable)
		}

		actionID := e.cachedActionTargetID(binding.SourceActionID, namespace)
		if actionID == "" {
			return nil, fmt.Errorf("%w: action %q target %q", ErrMissingMigratedTarget, binding.SourceActionID, namespaceLabel(namespace))
		}

		actionAttributeValue, err := registeredResourceActionAttributeValue(actionID, binding.AttributeValue)
		if err != nil {
			return nil, fmt.Errorf("registered resource value %q binding action %q: %w", valuePlan.Source.GetId(), binding.SourceActionID, err)
		}
		actionAttributeValues = append(actionAttributeValues, actionAttributeValue)
	}

	return actionAttributeValues, nil
}

func registeredResourceActionAttributeValue(actionID string, attributeValue *policy.Value) (*registeredresources.ActionAttributeValue, error) {
	if strings.TrimSpace(actionID) == "" {
		return nil, errors.New("action target id is empty")
	}
	if attributeValue == nil {
		return nil, errors.New("attribute value is missing")
	}

	actionAttributeValue := &registeredresources.ActionAttributeValue{
		ActionIdentifier: &registeredresources.ActionAttributeValue_ActionId{
			ActionId: actionID,
		},
	}

	if attributeValueID := strings.TrimSpace(attributeValue.GetId()); attributeValueID != "" {
		actionAttributeValue.AttributeValueIdentifier = &registeredresources.ActionAttributeValue_AttributeValueId{
			AttributeValueId: attributeValueID,
		}
		return actionAttributeValue, nil
	}

	if attributeValueFQN := strings.TrimSpace(attributeValue.GetFqn()); attributeValueFQN != "" {
		actionAttributeValue.AttributeValueIdentifier = &registeredresources.ActionAttributeValue_AttributeValueFqn{
			AttributeValueFqn: attributeValueFQN,
		}
		return actionAttributeValue, nil
	}

	return nil, errors.New("attribute value identifier is missing")
}

func registeredResourceValueIDsByValue(resource *policy.RegisteredResource) map[string]string {
	valueIDs := make(map[string]string)
	if resource == nil {
		return valueIDs
	}

	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}
		valueIDs[registeredResourceValueKey(value.GetValue())] = value.GetId()
	}

	return valueIDs
}

func registeredResourceValueKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
