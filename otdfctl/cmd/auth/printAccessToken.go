package auth

import (
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/auth"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/spf13/cobra"
)

func printAccessTokenRun(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	cp := common.InitProfile(c)

	ac := cp.GetAuthCredentials()
	switch ac.AuthType {
	case profiles.AuthTypeClientCredentials:
		c.Printf("Getting access token for %s... ", ac.ClientID)
	case profiles.AuthTypeAccessToken:
		c.Printf("Getting profile's stored access token... ")
	default:
		c.ExitWithError("Invalid auth type", nil)
	}
	tok, err := auth.GetTokenWithProfile(cmd.Context(), cp)
	if err != nil {
		c.Println("failed")
		cli.ExitWithError("Failed to get token", err)
	}
	c.Println("ok")
	c.Printf("Access Token: %s\n", tok.AccessToken)

	c.PrintIfJSON(tok)
}

// newPrintAccessTokenCmd creates and configures the print-access-token command.
func newPrintAccessTokenCmd() *cobra.Command {
	doc := man.Docs.GetCommand("auth/print-access-token", man.WithRun(printAccessTokenRun))
	return &doc.Command
}
