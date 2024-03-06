package cmd

import (
	"os"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt string to tdf",
	RunE:  encrypt,
	Args:  cobra.MinimumNArgs(1),
}

func encrypt(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	plainText := args[0]

	// Create new offline client
	client, err := sdk.New("")
	if err != nil {
		return err
	}

	tdfFile, err := os.Create("sensitive.txt.tdf")
	if err != nil {
		return err
	}

	// Encrypt the plain text

	return nil
}
