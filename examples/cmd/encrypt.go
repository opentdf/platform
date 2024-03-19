package cmd

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Create encrypted TDF",
	RunE:  encrypt,
	Args:  cobra.MinimumNArgs(1),
}

func init() {
	ExamplesCmd.AddCommand(encryptCmd)
}

func encrypt(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	plainText := args[0]
	strReader := strings.NewReader(plainText)

	// Create new offline client

	client, err := sdk.New(cmd.Context().Value(RootConfigKey).(*ExampleConfig).PlatformEndpoint,
		sdk.WithInsecureConn(),
		sdk.WithClientCredentials("opentdf", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	)
	if err != nil {
		return err
	}

	tdfFile, err := os.Create("sensitive.txt.tdf")
	if err != nil {
		return err
	}
	defer tdfFile.Close()

	tdf, err := client.CreateTDF(tdfFile, strReader,
		//sdk.WithDataAttributes("https://example.com/attributes/1", "https://example.com/attributes/2"),
		sdk.WithKasInformation(
			sdk.KASInfo{
				URL:       "http://localhost:8080",
				PublicKey: "",
			}))
	if err != nil {
		return err
	}

	manifestJSON, err := json.MarshalIndent(tdf.Manifest(), "", "  ")
	if err != nil {
		return err
	}

	// Print Manifest
	cmd.Println(string(manifestJSON))
	return nil
}
