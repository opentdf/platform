package auth

import (
	"fmt"
	"strings"

	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/auth"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/otdfctl/pkg/profiles"
	"github.com/spf13/cobra"
)

func clientCredentialsRun(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	cp := common.InitProfile(c)

	var clientID string
	var clientSecret string

	if len(args) > 0 {
		clientID = args[0]
	}
	if len(args) > 1 {
		clientSecret = args[1]
	}

	if clientID == "" {
		clientID = cli.AskForInput("Enter client id: ")
	}
	if clientSecret == "" {
		clientSecret = cli.AskForSecret("Enter client secret: ")
	}
	var scopes []string
	if cmd.Flags().Changed("scopes") {
		flagScopes, err := cmd.Flags().GetStringSlice("scopes")
		if err != nil {
			c.ExitWithError("Failed to read scopes flag", err)
		}
		scopes = make([]string, 0, len(flagScopes))
		for _, scope := range flagScopes {
			scopes = append(scopes, strings.TrimSpace(scope))
		}
	}

	// Set the client credentials
	err := cp.SetAuthCredentials(profiles.AuthCredentials{
		AuthType:     profiles.AuthTypeClientCredentials,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
	})
	if err != nil {
		c.ExitWithError("Failed to set client credentials", err)
	}

	// Validate the client credentials
	if err := auth.ValidateProfileAuthCredentials(cmd.Context(), cp); err != nil {
		c.ExitWithError("An error occurred during login. Please check your credentials and try again", err)
	}

	c.ExitWithMessage(fmt.Sprintf("Client credentials set for profile [%s]", cp.Name()), cli.ExitCodeSuccess)
}

// newClientCredentialsCmd creates and configures the client-credentials command.
func newClientCredentialsCmd() *cobra.Command {
	doc := man.Docs.GetCommand("auth/client-credentials",
		man.WithRun(clientCredentialsRun),
		man.WithHiddenFlags("with-client-creds", "with-client-creds-file"),
	)
	doc.Flags().StringSlice(
		doc.GetDocFlag("scopes").Name,
		[]string{},
		doc.GetDocFlag("scopes").Description,
	)
	return &doc.Command
}
