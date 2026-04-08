package migrate

import (
	"errors"

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
	doc.Flags().StringP(
		doc.GetDocFlag("output").Name,
		doc.GetDocFlag("output").Shorthand,
		doc.GetDocFlag("output").Default,
		doc.GetDocFlag("output").Description,
	)

	return &doc.Command
}

func migrateNamespacedPolicy(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	c.Flags.GetRequiredString("scope")
	c.Flags.GetRequiredString("output")

	cli.ExitWithError(
		"migrate namespaced-policy is not implemented",
		errors.New("the migrate namespaced-policy workflow is not implemented yet"),
	)
}
