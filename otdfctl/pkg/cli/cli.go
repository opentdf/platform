package cli

import (
	"context"

	"github.com/spf13/cobra"
)

type Cli struct {
	cmd  *cobra.Command
	args []string

	// Helpers
	Flags      *flagHelper
	FlagHelper *flagHelper
	printer    *Printer
}

// New creates a new Cli object
func New(cmd *cobra.Command, args []string, options ...cliVariadicOption) *Cli {
	opts := cliOptions{
		printerJSON: false,
	}
	for _, opt := range options {
		opts = opt(opts)
	}

	cli := &Cli{
		cmd:  cmd,
		args: args,
	}

	if cmd == nil {
		ExitWithError("cli expects a command", ErrPrinterExpectsCommand)
	}

	cli.Flags = newFlagHelper(cmd)
	// Temp wrapper for FlagHelper until we can remove it
	cli.FlagHelper = cli.Flags

	cli.printer = newPrinter(cli)
	if opts.printerJSON {
		cli.printer.setJSON(true)
	}

	return cli
}

func (c *Cli) Cmd() *cobra.Command {
	return c.cmd
}

func (c *Cli) Context() context.Context {
	return c.cmd.Context()
}
