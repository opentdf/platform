package cmd

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

// enforceArgs validates the complete command tree, including Cobra defaults.
func enforceArgs(root *cobra.Command) {
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	cli.EnforceSubcommandArgs(root)
}

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

	// Apply doc metadata after consumers finish assembling the command tree.
	man.Docs.MarkRequiredFlags()

	if c.mountTo != nil {
		err := MountRoot(c.mountTo, c.renameCmd)
		if err != nil {
			os.Exit(cli.ExitCodeError)
		}
		enforceArgs(c.mountTo)
		return
	}

	enforceArgs(RootCmd)

	// Format Cobra validation failures through the selected output mode.
	RootCmd.SilenceErrors = true
	RootCmd.SilenceUsage = true
	preserveJSONFlagOnError(RootCmd, os.Args[1:])
	cmd, err := RootCmd.ExecuteC()
	if err != nil {
		handleExecuteError(cmd, err)
	}
}

// preserveJSONFlagOnError preserves JSON mode when pflag stops at an earlier error.
func preserveJSONFlagOnError(root *cobra.Command, args []string) {
	handleFlagError := root.FlagErrorFunc()
	root.SetFlagErrorFunc(func(cmd *cobra.Command, flagErr error) error {
		if jsonOut, requested := requestedBoolFlag(cmd, args, "json"); requested {
			if err := root.PersistentFlags().Set("json", strconv.FormatBool(jsonOut)); err != nil {
				return errors.Join(flagErr, err)
			}
		}
		return handleFlagError(cmd, flagErr)
	})
}

func requestedBoolFlag(cmd *cobra.Command, args []string, name string) (bool, bool) {
	flag := "--" + name
	var value, found bool
	var consumeNext bool
	for _, arg := range args {
		if consumeNext {
			consumeNext = false
			continue
		}
		if arg == "--" {
			break
		}
		if arg == flag {
			value, found = true, true
			continue
		}
		raw, ok := strings.CutPrefix(arg, flag+"=")
		if !ok {
			consumeNext = flagConsumesNext(cmd, arg)
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err == nil {
			value, found = parsed, true
		}
	}
	return value, found
}

func flagConsumesNext(cmd *cobra.Command, arg string) bool {
	if name, ok := strings.CutPrefix(arg, "--"); ok {
		if strings.ContainsRune(name, '=') {
			return false
		}
		flag := cmd.Flag(name)
		return flag != nil && flag.NoOptDefVal == ""
	}
	if !strings.HasPrefix(arg, "-") || len(arg) < 2 {
		return false
	}

	flags := cmd.Flags()
	for i := 1; i < len(arg); i++ {
		flag := flags.ShorthandLookup(arg[i : i+1])
		if flag == nil {
			return false
		}
		if flag.NoOptDefVal == "" {
			return i == len(arg)-1
		}
	}
	return false
}

// handleExecuteError formats a Cobra error and exits with a nonzero status.
func handleExecuteError(cmd *cobra.Command, err error) {
	if cmd == nil {
		cmd = RootCmd
	}

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
