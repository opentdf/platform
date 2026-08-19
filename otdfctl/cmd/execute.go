package cmd

import (
	"errors"
	"os"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

type ExecuteConfig struct {
	mountTo   *cobra.Command
	renameCmd *cobra.Command
	cmdName   string
}
type ExecuteOptFunc func(c ExecuteConfig) ExecuteConfig

func WithMountTo(cmd *cobra.Command, renameCmd *cobra.Command) ExecuteOptFunc {
	if cmd == nil {
		panic("cmd is nil")
	}

	return func(c ExecuteConfig) ExecuteConfig {
		c.cmdName = cmd.Use
		if renameCmd.Use != "" {
			c.cmdName = renameCmd.Use
		}
		c.mountTo = cmd
		c.renameCmd = renameCmd
		return c
	}
}

func Execute(opts ...ExecuteOptFunc) {
	c := ExecuteConfig{}
	for _, opt := range opts {
		c = opt(c)
	}

	// Enforce `required: true` doc metadata at the cobra layer now that the whole
	// command tree is assembled. Done here (rather than in init) so commands added
	// after otdfctl's own init, including a consumer's, are covered.
	man.Docs.MarkRequiredFlags()

	if c.mountTo != nil {
		err := MountRoot(c.mountTo, c.renameCmd)
		if err != nil {
			os.Exit(cli.ExitCodeError)
		}
	} else {
		// Take over error printing so cobra-level failures (e.g. required or
		// mutually-exclusive flag validation, which run before the command
		// handler) still honor --json. Cobra would otherwise print plain text
		// and usage, producing invalid JSON for automation.
		RootCmd.SilenceErrors = true
		RootCmd.SilenceUsage = true
		cmd, err := RootCmd.ExecuteC()
		if err != nil {
			handleExecuteError(cmd, err)
		}
	}
}

// handleExecuteError formats an error returned from cobra's Execute. In --json
// mode it emits the standard JSON error envelope via cli.ExitWithError; otherwise
// it reproduces cobra's default output (the error followed by usage) on stderr.
// Either way it exits with a non-zero status.
func handleExecuteError(cmd *cobra.Command, err error) {
	if cmd == nil {
		cmd = RootCmd
	}

	// --json is a persistent flag on the root command, so it is inherited by the
	// executed command and parsed by the time Execute returns.
	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		cli.New(cmd, os.Args).ExitWithError(err.Error(), nil)
		return
	}

	cmd.PrintErrln("Error:", err.Error())
	cmd.PrintErrln(cmd.UsageString())
	os.Exit(cli.ExitCodeError)
}

func MountRoot(newRoot *cobra.Command, cmd *cobra.Command) error {
	if newRoot == nil {
		return errors.New("newRoot is nil")
	}

	if cmd != nil {
		RootCmd.Use = cmd.Use
		RootCmd.Short = cmd.Short
		RootCmd.Long = cmd.Long
	}

	newRoot.AddCommand(RootCmd)
	return nil
}
