package namespacedpolicy

import (
	"context"
	"fmt"
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

	return reviewUnresolvedPruneItems(ctx, prompter, plan.ObligationTriggers)
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

func reviewablePruneItem(item pruneReviewItem) bool {
	return item.hasSource() && item.status() == PruneStatusUnresolved
}

func markPruneItemDelete(item pruneReviewItem) {
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
		Kind:        "action",
		Label:       p.Source.GetName(),
		Description: renderPruneReviewDescription(p.pruneDetails(false, nil), p.Reason, p.Execution),
	}
}

func (p *PruneSubjectConditionSetPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:        "subject condition set",
		Label:       p.Source.GetId(),
		Description: renderPruneReviewDescription(p.pruneDetails(false, nil), p.Reason, p.Execution),
	}
}

func (p *PruneSubjectMappingPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:        "subject mapping",
		Label:       p.Source.GetId(),
		Description: renderPruneReviewDescription(p.pruneDetails(false, nil), p.Reason, p.Execution),
	}
}

func (p *PruneRegisteredResourcePlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:        "registered resource",
		Label:       p.Source.GetName(),
		Description: renderPruneReviewDescription(p.pruneDetails(false, nil), p.Reason, p.Execution),
	}
}

func (p *PruneObligationTriggerPlan) reviewSummary() pruneReviewSummary {
	return pruneReviewSummary{
		Kind:        "obligation trigger",
		Label:       p.Source.GetId(),
		Description: renderPruneReviewDescription(p.pruneDetails(false, nil), p.Reason, p.Execution),
	}
}

func pruneReviewOptions() []PromptOption {
	return []PromptOption{
		{Label: deletePruneLabel, Value: pruneReviewDelete, Description: deletePruneDescription},
		{Label: skipPruneLabel, Value: pruneReviewSkip, Description: skipPruneDescription},
		{Label: abortPruneLabel, Value: pruneReviewAbort, Description: abortPruneDescription},
	}
}
