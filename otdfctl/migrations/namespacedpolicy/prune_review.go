package namespacedpolicy

import (
	"context"
	"fmt"
	"strings"
)

const (
	pruneReviewDelete = "delete"
	pruneReviewSkip   = "skip"
	pruneReviewAbort  = "abort"

	deletePruneLabel       = "Delete source object"
	deletePruneDescription = "mark this unresolved item for deletion"
	skipPruneLabel         = "Skip this object"
	skipPruneDescription   = "leave this item unresolved and untouched"
	abortPruneLabel        = "Abort prune review"
	abortPruneDescription  = "stop without applying remaining decisions"
	pruneReasonText        = "Reason: "
	obligationText         = "Obligation: "
	contextText            = "Context: "
	filteredSourceText     = "Filtered source: "
	fullSourceText         = "Full source: "
	migratedTargetsText    = "Migrated targets: "
	migratedTargetText     = "Migrated target: "
)

type pruneReviewItem interface {
	prunePlanItem
	reviewSummary() pruneReviewSummary
}

type pruneReviewSummary struct {
	Kind        string
	Label       string
	Description []string
}

// ReviewPrunePlan prompts for every unresolved prune item and lets the user
// explicitly promote it to delete, leave it unresolved, or abort the run.
func ReviewPrunePlan(ctx context.Context, plan *PrunePlan, prompter InteractivePrompter) error {
	if plan == nil {
		return nil
	}
	if prompter == nil {
		prompter = &HuhPrompter{}
	}

	if err := reviewUnresolvedPruneItems(ctx, prompter, plan.Actions); err != nil {
		return err
	}
	if err := reviewUnresolvedPruneItems(ctx, prompter, plan.SubjectConditionSets); err != nil {
		return err
	}
	if err := reviewUnresolvedPruneItems(ctx, prompter, plan.SubjectMappings); err != nil {
		return err
	}
	if err := reviewUnresolvedPruneItems(ctx, prompter, plan.RegisteredResources); err != nil {
		return err
	}
	if err := reviewUnresolvedPruneItems(ctx, prompter, plan.ObligationTriggers); err != nil {
		return err
	}

	return nil
}

func reviewUnresolvedPruneItems[T pruneReviewItem](
	ctx context.Context,
	prompter InteractivePrompter,
	items []T,
) error {
	for _, item := range items {
		if !reviewablePruneItem(item) {
			continue
		}
		prompt := pruneReviewPrompt(item)
		if err := applyPruneReviewDecision(ctx, prompter, prompt, func() { markPruneItemDelete(item) }); err != nil {
			return err
		}
	}

	return nil
}

func reviewablePruneItem[T pruneReviewItem](item T) bool {
	return item.hasSource() && item.status() == PruneStatusUnresolved
}

func markPruneItemDelete[T pruneReviewItem](item T) {
	item.setStatus(PruneStatusDelete)
	item.setReason(PruneStatusReason{})
}

func applyPruneReviewDecision(ctx context.Context, prompter InteractivePrompter, prompt SelectPrompt, markDelete func()) error {
	choice, err := prompter.Select(ctx, prompt)
	if err != nil {
		return err
	}

	switch choice {
	case pruneReviewDelete:
		markDelete()
		return nil
	case pruneReviewSkip:
		return nil
	case pruneReviewAbort:
		return ErrInteractiveReviewAborted
	default:
		return fmt.Errorf("invalid prune review selection %q", choice)
	}
}

func pruneReviewPrompt(item pruneReviewItem) SelectPrompt {
	summary := item.reviewSummary()

	return SelectPrompt{
		Title:       fmt.Sprintf("Delete unresolved %s %q?", summary.Kind, summary.Label),
		Description: summary.Description,
		Options:     pruneReviewOptions(),
	}
}

func (p *PruneActionPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:  "action",
		Label: p.Source.GetName(),
		Description: []string{
			sourceIDText + p.Source.GetId(),
			actionText + p.Source.GetName(),
			migratedTargetsText + targetRefsSummary(p.MigratedTargets),
			pruneReasonText + p.Reason.String(),
		},
	}
}

func (p *PruneSubjectConditionSetPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:  "subject condition set",
		Label: p.Source.GetId(),
		Description: []string{
			sourceIDText + p.Source.GetId(),
			migratedTargetsText + targetRefsSummary(p.MigratedTargets),
			pruneReasonText + p.Reason.String(),
		},
	}
}

func (p *PruneSubjectMappingPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:  "subject mapping",
		Label: p.Source.GetId(),
		Description: []string{
			sourceIDText + p.Source.GetId(),
			attributeValueText + valueFQN(p.Source.GetAttributeValue()),
			scsSourceText + p.Source.GetSubjectConditionSet().GetId(),
			actionsText + plainPolicyActionNamesSummary(p.Source.GetActions()),
			migratedTargetText + p.MigratedTarget.String(),
			pruneReasonText + p.Reason.String(),
		},
	}
}

func (p *PruneRegisteredResourcePlan) reviewSummary() pruneReviewSummary {
	description := []string{
		sourceIDText + p.Source.GetId(),
		resourceText + p.Source.GetName(),
		migratedTargetText + p.MigratedTarget.String(),
	}
	if p.Reason.Type == PruneStatusReasonTypeRegisteredResourceSourceMismatch {
		description = append(description,
			filteredSourceText+plainRegisteredResourceSourceSummary(p.Source),
			fullSourceText+plainRegisteredResourceSourceSummary(p.FullSource),
		)
	}
	description = append(description, pruneReasonText+p.Reason.String())

	return pruneReviewSummary{
		Kind:        "registered resource",
		Label:       p.Source.GetName(),
		Description: description,
	}
}

func (p *PruneObligationTriggerPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:  "obligation trigger",
		Label: p.Source.GetId(),
		Description: []string{
			sourceIDText + p.Source.GetId(),
			attributeValueText + valueFQN(p.Source.GetAttributeValue()),
			actionText + actionLabel(p.Source.GetAction()),
			obligationText + obligationLabel(p.Source.GetObligationValue().GetObligation()),
			obligationValueText + obligationValueIDOrFQN(p.Source.GetObligationValue()),
			contextText + plainRequestContextsSummary(p.Source.GetContext()),
			migratedTargetText + p.MigratedTarget.String(),
			pruneReasonText + p.Reason.String(),
		},
	}
}

func pruneReviewOptions() []PromptOption {
	return []PromptOption{
		{Label: deletePruneLabel, Value: pruneReviewDelete, Description: deletePruneDescription},
		{Label: skipPruneLabel, Value: pruneReviewSkip, Description: skipPruneDescription},
		{Label: abortPruneLabel, Value: pruneReviewAbort, Description: abortPruneDescription},
	}
}

func targetRefsSummary(targets []TargetRef) string {
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		label := target.String()
		if label == noneLabel {
			continue
		}
		labels = append(labels, label)
	}
	if len(labels) == 0 {
		return noneLabel
	}
	return strings.Join(labels, ", ")
}
