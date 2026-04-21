package prune

import (
	"errors"

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
	c.Flags.GetRequiredString("scope")

	cli.ExitWithError(
		"migrate prune namespaced-policy is not implemented",
		errors.New("the migrate prune namespaced-policy workflow is not implemented yet"),
	)
}
