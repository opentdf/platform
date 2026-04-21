package migrate

import (
	otdfctl "github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/spf13/cobra"
)

func newRegisteredResourcesCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "registered-resources",
		Short:  "Legacy registered resource migration",
		Hidden: true,
		Args:   cobra.NoArgs,
		Run:    runRegisteredResources,
	}
}

func runRegisteredResources(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := otdfctl.NewHandler(c)
	defer h.Close()

	commit, err := cmd.InheritedFlags().GetBool("commit")
	if err != nil {
		cli.ExitWithError("could not read --commit flag", err)
	}

	interactive, err := cmd.InheritedFlags().GetBool("interactive")
	if err != nil {
		cli.ExitWithError("could not read --interactive flag", err)
	}

	if err := migrations.MigrateRegisteredResources(cmd.Context(), h, &migrations.HuhPrompter{}, commit, interactive); err != nil {
		cli.ExitWithError("could not migrate registered resources", err)
	}
}
