//nolint:forbidigo // print statements need flexibility
package dev

import (
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	// Command holding playground-style development
	devCmd = man.Docs.GetCommand("dev")

	Cmd = &devCmd.Command
)

func designSystemRun(cmd *cobra.Command, args []string) {
	fmt.Print("Design system\n=============\n\n")

	printDSComponent("Table", renderDSTable())

	printDSComponent("Messages", renderDSMessages())
}

func printDSComponent(title string, component string) {
	fmt.Printf("%s\n", title)
	fmt.Print("-----\n\n")
	fmt.Printf("%s\n", component)
	fmt.Print("\n\n")
}

func renderDSTable() string {
	tbl := cli.NewTable(
		table.NewFlexColumn("one", "One", cli.FlexColumnWidthOne),
		table.NewFlexColumn("two", "Two", cli.FlexColumnWidthOne),
		table.NewFlexColumn("three", "Three", cli.FlexColumnWidthOne),
	).WithRows([]table.Row{
		table.NewRow(table.RowData{
			"one":   "1",
			"two":   "2",
			"three": "3",
		}),
		table.NewRow(table.RowData{
			"one":   "4",
			"two":   "5",
			"three": "6",
		}),
	})
	return tbl.View()
}

func renderDSMessages() string {
	return cli.SuccessMessage("Success message") + "\n" + cli.ErrorMessage("Error message", nil)
}

func InitCommands() {
	designCmd := man.Docs.GetCommand("dev/design-system",
		man.WithRun(designSystemRun),
	)
	devCmd.AddCommand(&designCmd.Command)

	initSelectorsCommands()
}
