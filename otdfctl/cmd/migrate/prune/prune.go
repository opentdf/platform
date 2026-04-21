package prune

import (
	"github.com/opentdf/platform/otdfctl/pkg/man"
)

var (
	pruneDoc = man.Docs.GetCommand("migrate/prune")

	Cmd = &pruneDoc.Command
)

func InitCommands() {
	Cmd.Hidden = true
	Cmd.AddCommand(pruneNamespacedPolicyCmd())
}
