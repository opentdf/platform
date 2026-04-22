//nolint:forbidigo // interactive migration review requires terminal prompts
package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	namespacedPolicyCommitConfirm = "confirm"
	namespacedPolicyCommitSkip    = "skip"
	namespacedPolicyCommitAbort   = "abort"
	noneLabel                     = "(none)"
	skippedByUserReason           = "skipped by user"

	//nolint:gosec // user-facing backup prompt text, not credentials
	backupWarningTitle  = "WARNING: This operation will migrate namespaced policy objects and may create new policy objects."
	backupWarningBody   = "It is STRONGLY recommended to take a complete backup of your system before proceeding.\n"
	backupConfirmTitle  = "Have you taken a complete backup?"
	backupConfirmDetail = "Commit mode will apply namespaced policy changes to the target system."
	backupAbortDetail   = "Choose abort if you have not created a backup yet."
	backupConfirmLabel  = "Yes, continue"
	backupCancelLabel   = "Abort"
	sourceIDText        = "Source ID: "
	actionText          = "Action: "
	actionsText         = "Actions: "
	resourceText        = "Resource: "
	targetNamespaceText = "Target namespace: "
	attributeValueText  = "Attribute value: "
	obligationValueText = "Obligation value: "
	valuesText          = "Values: "
	actionBindingsText  = "Action bindings: "
	existingTargetText  = "Existing target resource: "
	subjectSetsTextFmt  = "Subject sets: %d"
	scsSourceText       = "Subject condition set source: "

	createActionDescription            = "This will create a new namespaced action."
	createSubjectConditionSetDesc      = "This will create a new namespaced subject condition set."
	createSubjectMappingDescription    = "This will create a new namespaced subject mapping."
	reuseRegisteredResourceDescription = "This will reuse the existing parent registered resource and create any missing values."
	createRegisteredResourceDesc       = "This will create a new namespaced registered resource and its values."
	createObligationTriggerDesc        = "This will create a new namespaced obligation trigger."

	confirmMigrationLabel       = "Confirm migration"
	confirmMigrationDescription = "apply this create operation"
	skipObjectLabel             = "Skip this object"
	skipObjectDescription       = "leave this object untouched"
	abortMigrationLabel         = "Abort entire migration"
	abortMigrationDescription   = "stop without applying remaining changes"
)

var ErrNamespacedPolicyBackupNotConfirmed = errors.New("user did not confirm backup")

func ConfirmNamespacedPolicyBackup(ctx context.Context, prompter InteractivePrompter) error {
	if prompter == nil {
		prompter = &HuhPrompter{}
	}

	styles := migrations.NewDisplayStyles()
	fmt.Println(styles.Warning().Render(backupWarningTitle))
	fmt.Println(styles.Warning().Render(backupWarningBody))

	err := prompter.Confirm(ctx, ConfirmPrompt{
		Title: backupConfirmTitle,
		Description: []string{
			backupConfirmDetail,
			backupAbortDetail,
		},
		ConfirmLabel: backupConfirmLabel,
		CancelLabel:  backupCancelLabel,
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInteractiveReviewAborted) {
		return ErrNamespacedPolicyBackupNotConfirmed
	}
	return err
}

func ReviewNamespacedPolicyInteractiveCommit(ctx context.Context, plan *Plan, prompter InteractivePrompter) error {
	if plan == nil {
		return nil
	}
	if prompter == nil {
		prompter = &HuhPrompter{}
	}

	state := interactiveCommitReviewState{
		skippedActions: make(map[string]map[string]string),
		skippedSCS:     make(map[string]map[string]string),
	}

	for _, actionPlan := range plan.Actions {
		if actionPlan == nil || actionPlan.Source == nil {
			continue
		}
		for _, target := range actionPlan.Targets {
			if target == nil || target.Status != TargetStatusCreate {
				continue
			}
			switch err := applyInteractiveDecision(ctx, prompter, actionPrompt(actionPlan, target)); {
			case err == nil:
			case errors.Is(err, errInteractiveSkipSelected):
				markActionTargetSkipped(actionPlan, target, skippedByUserReason)
				state.recordSkippedAction(actionPlan.Source.GetId(), target.Namespace, skippedReason("action", actionPlan.Source.GetName(), target.Namespace, skippedByUserReason))
			default:
				return err
			}
		}
	}

	for _, scsPlan := range plan.SubjectConditionSets {
		if scsPlan == nil || scsPlan.Source == nil {
			continue
		}
		for _, target := range scsPlan.Targets {
			if target == nil || target.Status != TargetStatusCreate {
				continue
			}
			switch err := applyInteractiveDecision(ctx, prompter, subjectConditionSetPrompt(scsPlan, target)); {
			case err == nil:
			case errors.Is(err, errInteractiveSkipSelected):
				markSubjectConditionSetTargetSkipped(scsPlan, target, skippedByUserReason)
				state.recordSkippedSCS(scsPlan.Source.GetId(), target.Namespace, skippedReason("subject condition set", scsPlan.Source.GetId(), target.Namespace, skippedByUserReason))
			default:
				return err
			}
		}
	}

	for _, mappingPlan := range plan.SubjectMappings {
		if mappingPlan == nil || mappingPlan.Source == nil || mappingPlan.Target == nil {
			continue
		}
		if mappingPlan.Target.Status != TargetStatusCreate {
			continue
		}
		if reason := state.subjectMappingSkipReason(mappingPlan); reason != "" {
			markSubjectMappingTargetSkipped(mappingPlan, reason)
			continue
		}
		switch err := applyInteractiveDecision(ctx, prompter, subjectMappingPrompt(plan, mappingPlan)); {
		case err == nil:
		case errors.Is(err, errInteractiveSkipSelected):
			markSubjectMappingTargetSkipped(mappingPlan, skippedByUserReason)
		default:
			return err
		}
	}

	for _, resourcePlan := range plan.RegisteredResources {
		if resourcePlan == nil || resourcePlan.Source == nil || resourcePlan.Target == nil {
			continue
		}
		if resourcePlan.Target.Status != TargetStatusCreate {
			continue
		}
		if reason := state.registeredResourceSkipReason(resourcePlan); reason != "" {
			markRegisteredResourceTargetSkipped(resourcePlan, reason)
			continue
		}
		switch err := applyInteractiveDecision(ctx, prompter, registeredResourcePrompt(plan, resourcePlan)); {
		case err == nil:
		case errors.Is(err, errInteractiveSkipSelected):
			markRegisteredResourceTargetSkipped(resourcePlan, skippedByUserReason)
		default:
			return err
		}
	}

	for _, triggerPlan := range plan.ObligationTriggers {
		if triggerPlan == nil || triggerPlan.Source == nil || triggerPlan.Target == nil {
			continue
		}
		if triggerPlan.Target.Status != TargetStatusCreate {
			continue
		}
		if reason := state.obligationTriggerSkipReason(triggerPlan); reason != "" {
			markObligationTriggerTargetSkipped(triggerPlan, reason)
			continue
		}
		switch err := applyInteractiveDecision(ctx, prompter, obligationTriggerPrompt(plan, triggerPlan)); {
		case err == nil:
		case errors.Is(err, errInteractiveSkipSelected):
			markObligationTriggerTargetSkipped(triggerPlan, skippedByUserReason)
		default:
			return err
		}
	}

	return nil
}

var errInteractiveSkipSelected = errors.New("interactive commit target skipped by user")

type interactiveCommitReviewState struct {
	skippedActions map[string]map[string]string
	skippedSCS     map[string]map[string]string
}

func (s *interactiveCommitReviewState) recordSkippedAction(sourceID string, namespace *policy.Namespace, reason string) {
	recordSkippedTargetReason(s.skippedActions, sourceID, namespace, reason)
}

func (s *interactiveCommitReviewState) recordSkippedSCS(sourceID string, namespace *policy.Namespace, reason string) {
	recordSkippedTargetReason(s.skippedSCS, sourceID, namespace, reason)
}

func (s *interactiveCommitReviewState) subjectMappingSkipReason(mappingPlan *SubjectMappingPlan) string {
	if mappingPlan == nil || mappingPlan.Target == nil {
		return ""
	}
	for _, sourceActionID := range mappingPlan.Target.ActionSourceIDs {
		if reason := skippedTargetReason(s.skippedActions, sourceActionID, mappingPlan.Target.Namespace); reason != "" {
			return reason
		}
	}
	if reason := skippedTargetReason(s.skippedSCS, mappingPlan.Target.SubjectConditionSetSourceID, mappingPlan.Target.Namespace); reason != "" {
		return reason
	}
	return ""
}

func (s *interactiveCommitReviewState) registeredResourceSkipReason(resourcePlan *RegisteredResourcePlan) string {
	if resourcePlan == nil || resourcePlan.Target == nil {
		return ""
	}
	for _, valuePlan := range resourcePlan.Target.Values {
		if valuePlan == nil {
			continue
		}
		for _, binding := range valuePlan.ActionBindings {
			if binding == nil {
				continue
			}
			if reason := skippedTargetReason(s.skippedActions, binding.SourceActionID, resourcePlan.Target.Namespace); reason != "" {
				return reason
			}
		}
	}
	return ""
}

func (s *interactiveCommitReviewState) obligationTriggerSkipReason(triggerPlan *ObligationTriggerPlan) string {
	if triggerPlan == nil || triggerPlan.Target == nil {
		return ""
	}
	return skippedTargetReason(s.skippedActions, triggerPlan.Target.ActionSourceID, triggerPlan.Target.Namespace)
}

func recordSkippedTargetReason(store map[string]map[string]string, sourceID string, namespace *policy.Namespace, reason string) {
	if strings.TrimSpace(sourceID) == "" {
		return
	}
	namespaceKey := interactiveReviewNamespaceKey(namespace)
	if namespaceKey == "" {
		return
	}
	if store[sourceID] == nil {
		store[sourceID] = make(map[string]string)
	}
	store[sourceID][namespaceKey] = reason
}

func skippedTargetReason(store map[string]map[string]string, sourceID string, namespace *policy.Namespace) string {
	if strings.TrimSpace(sourceID) == "" {
		return ""
	}
	namespaceKey := interactiveReviewNamespaceKey(namespace)
	if namespaceKey == "" {
		return ""
	}
	if store[sourceID] == nil {
		return ""
	}
	return store[sourceID][namespaceKey]
}

func interactiveReviewNamespaceKey(namespace *policy.Namespace) string {
	if namespace == nil {
		return ""
	}
	if id := strings.TrimSpace(namespace.GetId()); id != "" {
		return id
	}
	return strings.ToLower(strings.TrimSpace(namespace.GetFqn()))
}

func applyInteractiveDecision(ctx context.Context, prompter InteractivePrompter, prompt SelectPrompt) error {
	choice, err := prompter.Select(ctx, prompt)
	if err != nil {
		return err
	}

	switch choice {
	case namespacedPolicyCommitConfirm:
		return nil
	case namespacedPolicyCommitSkip:
		return errInteractiveSkipSelected
	case namespacedPolicyCommitAbort:
		return ErrInteractiveReviewAborted
	default:
		return fmt.Errorf("invalid interactive commit selection %q", choice)
	}
}

func actionPrompt(actionPlan *ActionPlan, target *ActionTargetPlan) SelectPrompt {
	return SelectPrompt{
		Title: fmt.Sprintf("Migrate action %q to %s?", actionPlan.Source.GetName(), namespaceDisplay(target.Namespace)),
		Description: []string{
			sourceIDText + actionPlan.Source.GetId(),
			actionText + actionPlan.Source.GetName(),
			targetNamespaceText + namespaceDisplay(target.Namespace),
			createActionDescription,
		},
		Options: confirmSkipAbortOptions(),
	}
}

func subjectConditionSetPrompt(scsPlan *SubjectConditionSetPlan, target *SubjectConditionSetTargetPlan) SelectPrompt {
	return SelectPrompt{
		Title: fmt.Sprintf("Migrate subject condition set %q to %s?", scsPlan.Source.GetId(), namespaceDisplay(target.Namespace)),
		Description: []string{
			sourceIDText + scsPlan.Source.GetId(),
			targetNamespaceText + namespaceDisplay(target.Namespace),
			fmt.Sprintf(subjectSetsTextFmt, len(scsPlan.Source.GetSubjectSets())),
			createSubjectConditionSetDesc,
		},
		Options: confirmSkipAbortOptions(),
	}
}

func subjectMappingPrompt(plan *Plan, mappingPlan *SubjectMappingPlan) SelectPrompt {
	return SelectPrompt{
		Title: fmt.Sprintf("Migrate subject mapping %q to %s?", mappingPlan.Source.GetId(), namespaceDisplay(mappingPlan.Target.Namespace)),
		Description: []string{
			sourceIDText + mappingPlan.Source.GetId(),
			targetNamespaceText + namespaceDisplay(mappingPlan.Target.Namespace),
			attributeValueText + valueFQN(mappingPlan.Source.GetAttributeValue()),
			actionsText + plainActionNamesSummary(plan, mappingPlan.Target.ActionSourceIDs),
			scsSourceText + mappingPlan.Target.SubjectConditionSetSourceID,
			createSubjectMappingDescription,
		},
		Options: confirmSkipAbortOptions(),
	}
}

func registeredResourcePrompt(plan *Plan, resourcePlan *RegisteredResourcePlan) SelectPrompt {
	description := []string{
		sourceIDText + resourcePlan.Source.GetId(),
		resourceText + resourcePlan.Source.GetName(),
		targetNamespaceText + namespaceDisplay(resourcePlan.Target.Namespace),
		valuesText + plainRegisteredResourceValueFQNsSummary(resourcePlan),
		actionBindingsText + plainRegisteredResourceActionBindingsSummary(plan, resourcePlan),
	}
	if strings.TrimSpace(resourcePlan.Target.ExistingID) != "" {
		description = append(description,
			existingTargetText+resourcePlan.Target.ExistingID,
			reuseRegisteredResourceDescription,
		)
	} else {
		description = append(description, createRegisteredResourceDesc)
	}

	return SelectPrompt{
		Title:       fmt.Sprintf("Migrate registered resource %q to %s?", resourcePlan.Source.GetName(), namespaceDisplay(resourcePlan.Target.Namespace)),
		Description: description,
		Options:     confirmSkipAbortOptions(),
	}
}

func obligationTriggerPrompt(plan *Plan, triggerPlan *ObligationTriggerPlan) SelectPrompt {
	return SelectPrompt{
		Title: fmt.Sprintf("Migrate obligation trigger %q to %s?", triggerPlan.Source.GetId(), namespaceDisplay(triggerPlan.Target.Namespace)),
		Description: []string{
			sourceIDText + triggerPlan.Source.GetId(),
			targetNamespaceText + namespaceDisplay(triggerPlan.Target.Namespace),
			actionText + plainActionNamesSummary(plan, []string{triggerPlan.Target.ActionSourceID}),
			attributeValueText + valueFQN(triggerPlan.Source.GetAttributeValue()),
			obligationValueText + obligationValueIDOrFQN(triggerPlan.Source.GetObligationValue()),
			createObligationTriggerDesc,
		},
		Options: confirmSkipAbortOptions(),
	}
}

func confirmSkipAbortOptions() []PromptOption {
	return []PromptOption{
		{Label: confirmMigrationLabel, Value: namespacedPolicyCommitConfirm, Description: confirmMigrationDescription},
		{Label: skipObjectLabel, Value: namespacedPolicyCommitSkip, Description: skipObjectDescription},
		{Label: abortMigrationLabel, Value: namespacedPolicyCommitAbort, Description: abortMigrationDescription},
	}
}

func plainActionNamesSummary(plan *Plan, sourceIDs []string) string {
	names := make([]string, 0, len(sourceIDs))
	seen := make(map[string]struct{}, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		if strings.TrimSpace(sourceID) == "" {
			continue
		}
		name := actionNameBySourceID(plan, sourceID)
		if name == "" {
			name = sourceID
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, strconvQuote(name))
	}
	if len(names) == 0 {
		return noneLabel
	}
	return strings.Join(names, ", ")
}

func plainRegisteredResourceValueFQNsSummary(resource *RegisteredResourcePlan) string {
	values := make([]string, 0, len(resource.Target.Values))
	seen := make(map[string]struct{}, len(resource.Target.Values))
	for _, valuePlan := range resource.Target.Values {
		fqn := registeredResourceValueFQN(valuePlan)
		if strings.TrimSpace(fqn) == "" {
			continue
		}
		if _, ok := seen[fqn]; ok {
			continue
		}
		seen[fqn] = struct{}{}
		values = append(values, fqn)
	}
	if len(values) == 0 {
		return noneLabel
	}
	return strings.Join(values, ", ")
}

func plainRegisteredResourceActionBindingsSummary(plan *Plan, resource *RegisteredResourcePlan) string {
	bindings := make([]string, 0)
	seen := make(map[string]struct{})
	for _, valuePlan := range resource.Target.Values {
		if valuePlan == nil {
			continue
		}
		for _, binding := range valuePlan.ActionBindings {
			if binding == nil {
				continue
			}
			actionName := actionNameBySourceID(plan, binding.SourceActionID)
			if actionName == "" {
				actionName = binding.SourceActionID
			}
			label := fmt.Sprintf("%s -> %s", strconvQuote(actionName), valueFQN(binding.AttributeValue))
			if _, ok := seen[label]; ok {
				continue
			}
			seen[label] = struct{}{}
			bindings = append(bindings, label)
		}
	}
	if len(bindings) == 0 {
		return noneLabel
	}
	return strings.Join(bindings, ", ")
}

func markActionTargetSkipped(actionPlan *ActionPlan, target *ActionTargetPlan, reason string) {
	if actionPlan == nil || target == nil {
		return
	}
	target.Status = TargetStatusSkipped
	target.Reason = reason
}

func markSubjectConditionSetTargetSkipped(scsPlan *SubjectConditionSetPlan, target *SubjectConditionSetTargetPlan, reason string) {
	if scsPlan == nil || target == nil {
		return
	}
	target.Status = TargetStatusSkipped
	target.Reason = reason
}

func markSubjectMappingTargetSkipped(mappingPlan *SubjectMappingPlan, reason string) {
	if mappingPlan == nil || mappingPlan.Target == nil {
		return
	}
	mappingPlan.Target.Status = TargetStatusSkipped
	mappingPlan.Target.Reason = reason
}

func markRegisteredResourceTargetSkipped(resourcePlan *RegisteredResourcePlan, reason string) {
	if resourcePlan == nil || resourcePlan.Target == nil {
		return
	}
	resourcePlan.Target.Status = TargetStatusSkipped
	resourcePlan.Target.Reason = reason
}

func markObligationTriggerTargetSkipped(triggerPlan *ObligationTriggerPlan, reason string) {
	if triggerPlan == nil || triggerPlan.Target == nil {
		return
	}
	triggerPlan.Target.Status = TargetStatusSkipped
	triggerPlan.Target.Reason = reason
}

func skippedReason(kind, label string, namespace *policy.Namespace, detail string) string {
	base := fmt.Sprintf("depends on skipped %s %q in %s", kind, label, namespaceDisplay(namespace))
	if strings.TrimSpace(detail) == "" {
		return base
	}
	return fmt.Sprintf("%s: %s", base, detail)
}
