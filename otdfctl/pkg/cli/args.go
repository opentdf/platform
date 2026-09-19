package cli

import (
	"github.com/spf13/cobra"
)

// AnnotationHelpOnly marks a command whose Run only prints help.
const AnnotationHelpOnly = "help-only"

const annotationTrue = "true"

// helpOnlyRun prints a group command's help.
func helpOnlyRun(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

// EnforceSubcommandArgs makes unknown group subcommands fail validation.
func EnforceSubcommandArgs(cmd *cobra.Command) {
	for _, sub := range cmd.Commands() {
		EnforceSubcommandArgs(sub)
	}
	if cmd.Runnable() || !cmd.HasSubCommands() {
		return
	}
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
