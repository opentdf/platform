package auth

import (
	"fmt"

	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/auth"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/otdfctl/pkg/profiles"
	"github.com/spf13/cobra"
)

func codeLogin(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	cp := common.InitProfile(c)
	clientID := c.FlagHelper.GetRequiredString("client-id")
	port := c.FlagHelper.GetOptionalString("port")
	tok, err := auth.LoginWithPKCE(
		cmd.Context(),
		cp.GetEndpoint(),
		clientID,
		c.FlagHelper.GetOptionalBool("tls-no-verify"),
		port,
	)
	if err != nil {
		c.ExitWithError("could not authenticate", err)
	}

	// Set the auth credentials to profile
	if err := cp.SetAuthCredentials(profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     clientID,
			AccessToken:  tok.AccessToken,
			Expiration:   tok.Expiry.Unix(),
			RefreshToken: tok.RefreshToken,
		},
	}); err != nil {
		c.ExitWithError("failed to set auth credentials", err)
	}
	c.ExitWithMessage(fmt.Sprintf("Code login complete for profile: [%s]", cp.Name()), cli.ExitCodeSuccess)
}

// newLoginCmd creates and configures the login command with all flags.
func newLoginCmd() *cobra.Command {
	doc := man.Docs.GetCommand("auth/login", man.WithRun(codeLogin))

	// Register flags
	doc.Flags().StringP(
		doc.GetDocFlag("client-id").Name,
		doc.GetDocFlag("client-id").Shorthand,
		doc.GetDocFlag("client-id").Default,
		doc.GetDocFlag("client-id").Description,
	)

	// intentionally a string flag to support an empty port which represents a dynamic port
	doc.Flags().StringP(
		doc.GetDocFlag("port").Name,
		doc.GetDocFlag("port").Shorthand,
		doc.GetDocFlag("port").Default,
		doc.GetDocFlag("port").Description,
	)

	return &doc.Command
}
