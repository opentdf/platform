package cmd

import (
	"fmt"
	"os"

	"github.com/opentdf/otdfctl/pkg/cli"
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
		return fmt.Errorf("newRoot is nil")
	}

	if cmd != nil {
		RootCmd.Use = cmd.Use
		RootCmd.Short = cmd.Short
		RootCmd.Long = cmd.Long
	}

	newRoot.AddCommand(RootCmd)
	return nil
}
