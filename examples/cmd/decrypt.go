package cmd

import (
	"io"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

func init() {
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt TDF file",
		RunE:  decrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	ExamplesCmd.AddCommand(decryptCmd)
}

func decrypt(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	tdfFile := args[0]

	// Create new client
	client, err := sdk.New(cmd.Context().Value(RootConfigKey).(*ExampleConfig).PlatformEndpoint,
		sdk.WithInsecureConn(),
		sdk.WithClientCredentials("opentdf", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	)
	if err != nil {
		return err
	}
	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}

	defer file.Close()

	tdfreader, err := client.LoadTDF(file)
	if err != nil {
		return err
	}
	buf := new(strings.Builder)
	_, err = io.Copy(buf, tdfreader)
	if err != nil && err != io.EOF {
		return err
	}

	//Print decrypted string
	cmd.Println(buf.String())
	return nil
}
