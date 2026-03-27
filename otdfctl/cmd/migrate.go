package cmd

import (
	otdfctl "github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

func withMigrateSubcommand(root *cobra.Command) {
	migrateDoc := man.Docs.GetDoc("migrate")
	migrateCmd := &cobra.Command{
		Use:   migrateDoc.Use,
		Short: migrateDoc.Short,
		Long:  migrateDoc.Long,
	}

	migrateCmd.PersistentFlags().BoolP(
		migrateDoc.GetDocFlag("commit").Name,
		migrateDoc.GetDocFlag("commit").Shorthand,
		migrateDoc.GetDocFlag("commit").DefaultAsBool(),
		migrateDoc.GetDocFlag("commit").Description,
	)

	migrateCmd.PersistentFlags().BoolP(
		migrateDoc.GetDocFlag("interactive").Name,
		migrateDoc.GetDocFlag("interactive").Shorthand,
		migrateDoc.GetDocFlag("interactive").DefaultAsBool(),
		migrateDoc.GetDocFlag("interactive").Description,
	)

	registeredResourcesMigrationCmd := man.Docs.GetCommand("migrate/registered-resources", man.WithRun(migrateRegisteredResources))

	migrateCmd.AddCommand(&registeredResourcesMigrationCmd.Command)

	root.AddCommand(migrateCmd)
}

func migrateRegisteredResources(cmd *cobra.Command, args []string) {
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
