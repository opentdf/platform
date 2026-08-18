//nolint:forbidigo // interactive migration review requires terminal prompts
package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/otdfctl/migrations"
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

	//nolint:gosec // user-facing backup prompt text, not credentials
	pruneBackupWarningTitle  = "WARNING: This operation will prune migrated namespaced policy and permanently delete legacy policy objects."
	pruneBackupConfirmDetail = "Commit mode will delete legacy/global policy objects from the target system."
	skipObjectLabel          = "Skip this object"
	skipObjectDescription    = "leave this object untouched"
)

var (
	ErrNamespacedPolicyBackupNotConfirmed = errors.New("user did not confirm backup")
	errInteractiveSkipSelected            = errors.New("interactive commit target skipped by user")
)

func ConfirmNamespacedPolicyBackup(ctx context.Context, prompter InteractivePrompter) error {
	return confirmNamespacedPolicyBackup(ctx, prompter, backupWarningTitle, backupConfirmDetail)
}

func ConfirmNamespacedPolicyPruneBackup(ctx context.Context, prompter InteractivePrompter) error {
	return confirmNamespacedPolicyBackup(ctx, prompter, pruneBackupWarningTitle, pruneBackupConfirmDetail)
}

func confirmNamespacedPolicyBackup(ctx context.Context, prompter InteractivePrompter, warningTitle, confirmDetail string) error {
	if prompter == nil {
		prompter = &HuhPrompter{}
	}

	styles := migrations.NewDisplayStyles()
	fmt.Println(styles.Warning().Render(warningTitle))
	fmt.Println(styles.Warning().Render(backupWarningBody))

	err := prompter.Confirm(ctx, ConfirmPrompt{
		Title: backupConfirmTitle,
		Description: []string{
			confirmDetail,
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
