package cmd

import (
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/otdfctl/tui"
	"github.com/spf13/cobra"
)

// newInteractiveCmd creates and configures the interactive command.
func newInteractiveCmd() *cobra.Command {
	doc := man.Docs.GetCommand("interactive",
		man.WithRun(func(cmd *cobra.Command, args []string) {
			c := cli.New(cmd, args)
			h := common.NewHandler(c)
			//nolint:errcheck // error does not need to be checked
			tui.StartTea(h)
		}),
	)
	return &doc.Command
}
