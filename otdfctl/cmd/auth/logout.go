package auth

import (
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/auth"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/spf13/cobra"
)

func logout(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	cp := common.InitProfile(c)
	c.Println("Initiating logout...")

	// we can only revoke access tokens stored for the code login flow, not client credentials
	creds := cp.GetAuthCredentials()
	if creds.AuthType == profiles.AuthTypeAccessToken {
		c.Println("Revoking access token...")
		if err := auth.RevokeAccessToken(
			cmd.Context(),
			cp.GetEndpoint(),
			creds.AccessToken.ClientID,
			creds.AccessToken.RefreshToken,
			c.FlagHelper.GetOptionalBool("tls-no-verify"),
		); err != nil {
			c.Println("failed")
			c.ExitWithError("An error occurred while revoking the access token", err)
		}
	}

	if err := cp.SetAuthCredentials(profiles.AuthCredentials{}); err != nil {
		c.Println("failed")
		c.ExitWithError("An error occurred while logging out", err)
	}
	c.Println("ok")
}

// newLogoutCmd creates and configures the logout command.
func newLogoutCmd() *cobra.Command {
	doc := man.Docs.GetCommand("auth/logout", man.WithRun(logout))
	return &doc.Command
}
