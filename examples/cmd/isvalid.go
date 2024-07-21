package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

func init() {
	encryptCmd := cobra.Command{
		Use:   "isvalid",
		Short: "Check validity of a TDF",
		RunE:  isValid,
		Args:  cobra.MinimumNArgs(1),
	}

	ExamplesCmd.AddCommand(&encryptCmd)
}

func isValid(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return cmd.Usage()
	}

	filePath := args[0]
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	//opts := []sdk.Option{
	//	sdk.WithInsecurePlaintextConn(),
	//	sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
	//	sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	//}

	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	isValidTdf, err := client.IsValidTdf(file)

	if err != nil {
		return err
	}

	cmd.Println(isValidTdf)

	return nil
}
