package namespacedpolicy

import (
	"context"
	"fmt"
)

const (
	confirmPruneDeleteLabel       = "Confirm delete"
	confirmPruneDeleteDescription = "delete this source object"
	abortPruneDeleteLabel         = "Abort prune commit"
	abortPruneDeleteDescription   = "stop before deleting any objects"
)

// ConfirmPrunePlanDeletes prompts for every delete-status prune item before
// commit execution and lets the user confirm, skip, or abort.
func ConfirmPrunePlanDeletes(ctx context.Context, plan *PrunePlan, prompter InteractivePrompter) error {
	if plan == nil {
		return nil
	}
	if prompter == nil {
		prompter = &HuhPrompter{}
	}

	if err := confirmDeletePruneItems(ctx, prompter, plan.Actions); err != nil {
		return err
	}
	if err := confirmDeletePruneItems(ctx, prompter, plan.SubjectConditionSets); err != nil {
		return err
	}
	if err := confirmDeletePruneItems(ctx, prompter, plan.SubjectMappings); err != nil {
		return err
	}
	if err := confirmDeletePruneItems(ctx, prompter, plan.RegisteredResources); err != nil {
		return err
	}
	if err := confirmDeletePruneItems(ctx, prompter, plan.ObligationTriggers); err != nil {
		return err
	}

	return nil
}

func confirmDeletePruneItems[T pruneReviewItem](
	ctx context.Context,
	prompter InteractivePrompter,
	items []T,
) error {
	for _, item := range items {
		if !confirmablePruneDeleteItem(item) {
			continue
		}
		prompt := pruneDeleteConfirmationPrompt(item)
		if err := applyPruneDeleteConfirmationDecision(ctx, prompter, prompt, func() { markPruneItemSkipped(item) }); err != nil {
			return err
		}
	}

	return nil
}

func confirmablePruneDeleteItem[T pruneReviewItem](item T) bool {
	return item.hasSource() && item.status() == PruneStatusDelete
}

func markPruneItemSkipped[T pruneReviewItem](item T) {
	item.setStatus(PruneStatusSkipped)
	item.setReason(newPruneReason(PruneStatusReasonTypeSkippedByUser, pruneStatusReasonMessageSkippedByUser))
}

func applyPruneDeleteConfirmationDecision(ctx context.Context, prompter InteractivePrompter, prompt SelectPrompt, markSkipped func()) error {
	choice, err := prompter.Select(ctx, prompt)
	if err != nil {
		return err
	}

	switch choice {
	case namespacedPolicyCommitConfirm:
		return nil
	case namespacedPolicyCommitSkip:
		markSkipped()
		return nil
	case namespacedPolicyCommitAbort:
		return ErrInteractiveReviewAborted
	default:
		return fmt.Errorf("invalid prune commit selection %q", choice)
	}
}

func pruneDeleteConfirmationPrompt(item pruneReviewItem) SelectPrompt {
	summary := item.reviewSummary()

	return SelectPrompt{
		Title:       fmt.Sprintf("Delete %s %q?", summary.Kind, summary.Label),
		Description: summary.Description,
		Options:     pruneDeleteConfirmationOptions(),
	}
}

func pruneDeleteConfirmationOptions() []PromptOption {
	return []PromptOption{
		{Label: confirmPruneDeleteLabel, Value: namespacedPolicyCommitConfirm, Description: confirmPruneDeleteDescription},
		{Label: skipObjectLabel, Value: namespacedPolicyCommitSkip, Description: skipObjectDescription},
		{Label: abortPruneDeleteLabel, Value: namespacedPolicyCommitAbort, Description: abortPruneDeleteDescription},
	}
}
