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
		err := RootCmd.Execute()
		if err != nil {
			os.Exit(cli.ExitCodeError)
		}
	}
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
