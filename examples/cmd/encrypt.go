package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	nanoTDFCOnfig, err := client.NewNanoTDFConfig()
	if err != nil {
		return err
	}

	nanoTDFCOnfig.SetKasUrl(fmt.Sprintf("http://%s", cmd.Flag("platformEndpoint").Value.String()))
	nanoTDFCOnfig.SetAttributes(attributes)

	plaintData := "virtru!!"
	inBuf := bytes.NewBufferString(plaintData)
	bufReader := bytes.NewReader(inBuf.Bytes())
	tdfBuf := bytes.Buffer{}

	_, err = client.CreateNanoTDF(io.Writer(&tdfBuf), bufReader, *nanoTDFCOnfig)
	if err != nil {
		return err
	}

	inBuf = bytes.NewBuffer(tdfBuf.Bytes())
	nanoTDFReader := bytes.NewReader(inBuf.Bytes())
	outBuf := bytes.Buffer{}
	_, err = client.ReadNanoTDF(io.Writer(&outBuf), nanoTDFReader)
	if err != nil {
		return err
	}

	if plaintData == outBuf.String() {
		cmd.Println("✅NanoTDF test passed!")
	} else {
		cmd.Println("❌NanoTDF test failed!")
	}

	return nil
}
