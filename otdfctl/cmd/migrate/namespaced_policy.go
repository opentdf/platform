package migrate

import (
	"errors"

	otdfctl "github.com/opentdf/platform/otdfctl/cmd/common"
	namespacedpolicy "github.com/opentdf/platform/otdfctl/migrations/namespacedpolicy"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

func migrateNamespacedPolicyCmd() *cobra.Command {
	doc := man.Docs.GetCommand("migrate/namespaced-policy", man.WithRun(migrateNamespacedPolicy))
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

func migrateNamespacedPolicy(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	scopeCSV := c.Flags.GetRequiredString("scope")
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

	var plannerOpts []namespacedpolicy.Option
	if interactive {
		plannerOpts = append(plannerOpts, namespacedpolicy.WithInteractiveReviewer(namespacedpolicy.NewHuhInteractiveReviewer(&h, prompter)))
	}

	planner, err := namespacedpolicy.NewPlanner(&h, scopeCSV, plannerOpts...)
	if err != nil {
		cli.ExitWithError("could not create namespaced-policy planner", err)
	}

	plan, err := planner.Plan(cmd.Context())
	if err != nil {
		cli.ExitWithError("could not build namespaced-policy plan", err)
	}

	if commit {
		executeNamespacedPolicyCommit(cmd, h, plan, interactive, prompter)
	}

	if _, err := cmd.OutOrStdout().Write([]byte(namespacedpolicy.RenderNamespacedPolicySummary(plan, commit) + "\n")); err != nil {
		cli.ExitWithError("could not write namespaced-policy summary", err)
	}
}

func confirmNamespacedPolicyCommit(cmd *cobra.Command, plan *namespacedpolicy.Plan, interactive bool, prompter namespacedpolicy.InteractivePrompter) error {
	if !interactive {
		return nil
	}
	if err := namespacedpolicy.ConfirmNamespacedPolicyBackup(cmd.Context(), prompter); err != nil {
		return err
	}
	if err := namespacedpolicy.ReviewNamespacedPolicyInteractiveCommit(cmd.Context(), plan, prompter); err != nil {
		return err
	}
	return nil
}

func executeNamespacedPolicyCommit(cmd *cobra.Command, h namespacedpolicy.ExecutorHandler, plan *namespacedpolicy.Plan, interactive bool, prompter namespacedpolicy.InteractivePrompter) {
	if err := confirmNamespacedPolicyCommit(cmd, plan, interactive, prompter); err != nil {
		if errors.Is(err, namespacedpolicy.ErrNamespacedPolicyBackupNotConfirmed) || errors.Is(err, namespacedpolicy.ErrInteractiveReviewAborted) {
			writeNamespacedPolicySummary(cmd, plan, false, "aborted")
		}
		cli.ExitWithError("could not review namespaced-policy commit", err)
	}

	executor, err := namespacedpolicy.NewExecutor(h)
	if err != nil {
		cli.ExitWithError("could not create namespaced-policy executor", err)
	}

	if err := executor.Execute(cmd.Context(), plan); err != nil {
		writeNamespacedPolicySummary(cmd, plan, true, "failure")
		cli.ExitWithError("could not execute namespaced-policy commit", err)
	}
}

func writeNamespacedPolicySummary(cmd *cobra.Command, plan *namespacedpolicy.Plan, commit bool, result string) {
	if _, err := cmd.OutOrStdout().Write([]byte(namespacedpolicy.RenderNamespacedPolicySummaryWithResult(plan, commit, result) + "\n")); err != nil {
		cli.ExitWithError("could not write namespaced-policy summary", err)
	}
}
