package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	platformEndpoint := cmd.Context().Value(RootConfigKey).(*ExampleConfig).PlatformEndpoint
	kasUrl := fmt.Sprintf("http://%s", platformEndpoint)

	// Create new offline client
	client, err := sdk.New(
		platformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
		sdk.WithKnownKas([]sdk.KASInfo{
			sdk.KASInfo{
				// examples assume insecure http
				DialOptions: []grpc.DialOption{
					grpc.WithTransportCredentials(insecure.NewCredentials()),
				},
				URL:       kasUrl,
			},
		}),
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
		//sdk.WithDataAttributes("https://example.com/attr/attr1/value/value1"),
		client.WithKnownKas(kasUrl),
	)
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
