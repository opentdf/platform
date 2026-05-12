package prune

import (
	"errors"

	otdfctl "github.com/opentdf/platform/otdfctl/cmd/common"
	namespacedpolicy "github.com/opentdf/platform/otdfctl/migrations/namespacedpolicy"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

func pruneNamespacedPolicyCmd() *cobra.Command {
	doc := man.Docs.GetCommand("migrate/prune/namespaced-policy", man.WithRun(pruneNamespacedPolicy))
	doc.Args = cobra.NoArgs
	doc.Hidden = true
	doc.Flags().StringP(
		doc.GetDocFlag("scope").Name,
		doc.GetDocFlag("scope").Shorthand,
		doc.GetDocFlag("scope").Default,
		doc.GetDocFlag("scope").Description,
	)

	return &doc.Command
}

func pruneNamespacedPolicy(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	scope := c.Flags.GetRequiredString("scope")
	prompter := &namespacedpolicy.HuhPrompter{}

	commit, err := cmd.InheritedFlags().GetBool("commit")
	if err != nil {
		cli.ExitWithError("could not read --commit flag", err)
	}
	interactive, err := cmd.InheritedFlags().GetBool("interactive")
	if err != nil {
		cli.ExitWithError("could not read --interactive flag", err)
	}

	h := otdfctl.NewHandler(c)
	defer h.Close()

	planner, err := namespacedpolicy.NewPrunePlanner(&h, scope)
	if err != nil {
		cli.ExitWithError("could not create namespaced-policy prune planner", err)
	}

	plan, err := planner.Plan(cmd.Context())
	if err != nil {
		cli.ExitWithError("could not build namespaced-policy prune plan", err)
	}

	if interactive {
		if err := namespacedpolicy.ReviewPrunePlan(cmd.Context(), plan, prompter); err != nil {
			if errors.Is(err, namespacedpolicy.ErrInteractiveReviewAborted) {
				writeNamespacedPolicyPruneSummary(cmd, plan, false, "aborted")
			}
			cli.ExitWithError("could not review namespaced-policy prune plan", err)
		}
	}

	if commit {
		executeNamespacedPolicyPruneCommit(cmd, h, plan, interactive, prompter)
	}

	if _, err := cmd.OutOrStdout().Write([]byte(namespacedpolicy.RenderNamespacedPolicyPruneSummary(plan, commit) + "\n")); err != nil {
		cli.ExitWithError("could not write namespaced-policy prune summary", err)
	}
}

func executeNamespacedPolicyPruneCommit(cmd *cobra.Command, h namespacedpolicy.ExecutorHandler, plan *namespacedpolicy.PrunePlan, interactive bool, prompter namespacedpolicy.InteractivePrompter) {
	if interactive {
		if err := namespacedpolicy.ConfirmNamespacedPolicyPruneBackup(cmd.Context(), prompter); err != nil {
			if errors.Is(err, namespacedpolicy.ErrNamespacedPolicyBackupNotConfirmed) {
				writeNamespacedPolicyPruneSummary(cmd, plan, false, "aborted")
			}
			cli.ExitWithError("could not confirm namespaced-policy prune backup", err)
		}
	}

	executor, err := namespacedpolicy.NewExecutor(h)
	if err != nil {
		cli.ExitWithError("could not create namespaced-policy prune executor", err)
	}

	if err := executor.ExecutePrune(cmd.Context(), plan); err != nil {
		writeNamespacedPolicyPruneSummary(cmd, plan, true, "failure")
		cli.ExitWithError("could not execute namespaced-policy prune commit", err)
	}
}

func writeNamespacedPolicyPruneSummary(cmd *cobra.Command, plan *namespacedpolicy.PrunePlan, commit bool, result string) {
	if _, err := cmd.OutOrStdout().Write([]byte(namespacedpolicy.RenderNamespacedPolicyPruneSummaryWithResult(plan, commit, result) + "\n")); err != nil {
		cli.ExitWithError("could not write namespaced-policy prune summary", err)
	}
}
