package cli

import (
	"github.com/spf13/cobra"
)

// AnnotationHelpOnly marks a command whose Run exists only to print help.
// EnforceSubcommandArgs adds it to every group it makes runnable, so tooling
// that walks the command tree can tell a real command from a help stub.
const AnnotationHelpOnly = "help-only"

// helpOnlyRun prints a group command's help.
func helpOnlyRun(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

// EnforceSubcommandArgs makes an unknown subcommand fail instead of quietly
// succeeding.
//
// Two cobra behaviors combine to hide the mistake. A command that has
// subcommands but no Run returns flag.ErrHelp, and ExecuteC swallows that
// error, so `otdfctl policy bogus` prints help and exits 0. The Runnable check
// also runs ahead of argument validation, so marking a group cobra.NoArgs on
// its own changes nothing. Giving each group a help-printing Run makes it
// runnable, at which point NoArgs reports the unknown subcommand the way a
// mistyped top-level command already does.
//
// Commands with a Run of their own are left untouched, as are the arguments of
// any command that already declares them.
func EnforceSubcommandArgs(cmd *cobra.Command) {
	for _, sub := range cmd.Commands() {
		EnforceSubcommandArgs(sub)
	}
	if cmd.Runnable() || !cmd.HasSubCommands() {
		return
	}
	// A group runs nothing, so it can never consume a positional argument.
	cmd.Args = cobra.NoArgs
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[AnnotationHelpOnly] = "true"
	cmd.RunE = helpOnlyRun
}

// IsHelpOnly reports whether cmd is a group whose Run only prints help.
func IsHelpOnly(cmd *cobra.Command) bool {
	return cmd.Annotations[AnnotationHelpOnly] == "true"
}
