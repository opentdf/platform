package migrate

import (
	"github.com/opentdf/platform/otdfctl/cmd/migrate/prune"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	migrateDoc = man.Docs.GetDoc("migrate")

	Cmd = &cobra.Command{
		Use:   migrateDoc.Use,
		Short: migrateDoc.Short,
		Long:  migrateDoc.Long,
	}
)

func InitCommands() {
	Cmd.PersistentFlags().BoolP(
		migrateDoc.GetDocFlag("commit").Name,
		migrateDoc.GetDocFlag("commit").Shorthand,
		migrateDoc.GetDocFlag("commit").DefaultAsBool(),
		migrateDoc.GetDocFlag("commit").Description,
	)

	Cmd.PersistentFlags().BoolP(
		migrateDoc.GetDocFlag("interactive").Name,
		migrateDoc.GetDocFlag("interactive").Shorthand,
		migrateDoc.GetDocFlag("interactive").DefaultAsBool(),
		migrateDoc.GetDocFlag("interactive").Description,
	)

	prune.InitCommands()

	Cmd.AddCommand(
		migrateNamespacedPolicyCmd(),
		prune.Cmd,
		newRegisteredResourcesCmd(), // TODO: Put this under a scope once we get there.
	)
}
