package cli

import (
	"github.com/spf13/cobra"
)

// AnnotationHelpOnly marks a command whose Run exists only to print help, so a
// consumer walking the tree can tell a stub from a real command. tructl's MCP
// tool generator reads it to keep groups out of the exposed tool set.
const AnnotationHelpOnly = "help-only"

const annotationTrue = "true"

// helpOnlyRun prints a group command's help.
func helpOnlyRun(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

// EnforceSubcommandArgs makes an unknown subcommand fail instead of quietly
// succeeding. Cobra checks Runnable() before it validates arguments, so NoArgs
// alone does nothing on a group; giving it a help-printing Run makes NoArgs
// apply. Commands with a Run of their own are left alone, as are any arguments
// already declared.
func EnforceSubcommandArgs(cmd *cobra.Command) {
	for _, sub := range cmd.Commands() {
		EnforceSubcommandArgs(sub)
	}
	if cmd.Runnable() || !cmd.HasSubCommands() {
		return
	}
	// A help stub takes no operands.
	cmd.Args = cobra.NoArgs
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[AnnotationHelpOnly] = annotationTrue
	cmd.RunE = helpOnlyRun
}

// IsHelpOnly reports whether cmd is a group whose Run only prints help.
func IsHelpOnly(cmd *cobra.Command) bool {
	return cmd.Annotations[AnnotationHelpOnly] == annotationTrue
}
