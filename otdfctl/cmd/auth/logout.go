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

func logout(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	cp := common.InitProfile(c)

	// we can only revoke access tokens stored for the code login flow, not client credentials
	creds := cp.GetAuthCredentials()
	if creds.AuthType == profiles.AuthTypeAccessToken {
		if err := auth.RevokeAccessToken(
			cmd.Context(),
			cp.GetEndpoint(),
			creds.AccessToken.ClientID,
			creds.AccessToken.RefreshToken,
			c.FlagHelper.GetOptionalBool("tls-no-verify"),
		); err != nil {
			c.ExitWithError("An error occurred while revoking the access token", err)
		}
	}

	if err := cp.SetAuthCredentials(profiles.AuthCredentials{}); err != nil {
		c.ExitWithError("An error occurred while logging out", err)
	}
	c.ExitWithMessage(fmt.Sprintf("Profile: [%s], logged out", cp.Name()), cli.ExitCodeSuccess)
}

// newLogoutCmd creates and configures the logout command.
func newLogoutCmd() *cobra.Command {
	doc := man.Docs.GetCommand("auth/logout", man.WithRun(logout))
	return &doc.Command
}
