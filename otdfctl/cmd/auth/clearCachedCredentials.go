package auth

import (
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

// newClearClientCredentialsCmd creates and configures the clear-client-credentials command.
func newClearClientCredentialsCmd() *cobra.Command {
	doc := man.Docs.GetCommand("auth/clear-client-credentials")
	return &doc.Command
}
