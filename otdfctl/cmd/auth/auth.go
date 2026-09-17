package auth

import (
	"runtime"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	authCmd = man.Docs.GetCommand("auth", man.WithHiddenFlags(
		"with-client-creds",
		"with-client-creds-file",
	))

	Cmd = &authCmd.Command
)

// keyringUnavailable reports whether cmd is about to touch keyring storage on a
// platform that has none.
//
// `otdfctl auth` itself only prints help. It reaches this hook at all because
// EnforceSubcommandArgs gives groups a Run so an unknown subcommand fails, and
// warning there would turn plain help into a non-zero exit.
func keyringUnavailable(cmd *cobra.Command, goos string) bool {
	return cmd != Cmd && goos == "linux"
}

func InitCommands() {
	authCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if keyringUnavailable(cmd, runtime.GOOS) {
			cli.ExitWithWarning(
				"Warning: Keyring storage is not available on Linux. Please use the `--with-client-creds` flag or the" +
					"`--with-client-creds-file` flag to provide client credentials securely.",
			)
		}
	}

	Cmd.AddCommand(newLoginCmd())
	Cmd.AddCommand(newLogoutCmd())
	Cmd.AddCommand(newClientCredentialsCmd())
	Cmd.AddCommand(newClearClientCredentialsCmd())
	Cmd.AddCommand(newPrintAccessTokenCmd())
}
