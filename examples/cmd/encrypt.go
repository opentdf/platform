package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/opentdf/platform/lib/ocrypto"

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
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
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
		sdk.WithDataAttributes("https://example.com/attr/attr1/value/value1"),
		sdk.WithKasInformation(
			sdk.KASInfo{
				// examples assume insecure http
				URL:       fmt.Sprintf("http://%s", cmd.Flag("platformEndpoint").Value.String()),
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

	//
	// NanoTDF
	//

	attributes := []string{
		"https://example.com/attr/attr1/value/value1",
	}

	nanoTDFCOnfig, err := client.NewNanoTDFConfig()
	if err != nil {
		return err
	}

	nanoTDFCOnfig.SetAttributes(attributes)
	nanoTDFCOnfig.SetKasURL(fmt.Sprintf("http://%s/kas", cmd.Flag("platformEndpoint").Value.String()))
	nanoTDFCOnfig.EnableECDSAPolicyBinding()

	nTDFile := "sensitive.txt.ntdf"
	strReader = strings.NewReader(plainText)
	nTdfFile, err := os.Create(nTDFile)
	defer nTdfFile.Close()

	_, err = client.CreateNanoTDF(nTdfFile, strReader, *nanoTDFCOnfig)
	if err != nil {
		return err
	}

	err = dumpNanoTDF(cmd, nTDFile)
	if err != nil {
		return err
	}
	return nil
}

func dumpNanoTDF(cmd *cobra.Command, nTdfFile string) error {
	f, err := os.Open(nTdfFile)
	if err != nil {
		return err
	}

	buf := bytes.Buffer{}
	_, err = buf.ReadFrom(f)
	if err != nil {
		return err
	}

	cmd.Println(string(ocrypto.Base64Encode(buf.Bytes())))

	return nil
}
