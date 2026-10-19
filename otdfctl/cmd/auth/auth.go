package auth

import "github.com/opentdf/platform/otdfctl/pkg/man"

var (
	authCmd = man.Docs.GetCommand("auth", man.WithHiddenFlags(
		"with-client-creds",
		"with-client-creds-file",
	))

	Cmd = &authCmd.Command
)

func InitCommands() {
	Cmd.AddCommand(newLoginCmd())
	Cmd.AddCommand(newLogoutCmd())
	Cmd.AddCommand(newClientCredentialsCmd())
	Cmd.AddCommand(newClearClientCredentialsCmd())
	Cmd.AddCommand(newPrintAccessTokenCmd())
}
