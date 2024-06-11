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

var (
	nanoFormat           bool
	noKIDInKAO           bool
	outputName           string
	joinedDataAttributes string
)

func init() {
	encryptCmd := cobra.Command{
		Use:   "encrypt",
		Short: "Create encrypted TDF",
		RunE:  encrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	encryptCmd.Flags().StringVarP(&joinedDataAttributes, "data-attributes", "a", "https://example.com/attr/attr1/value/value1", "space separated list of data attributes")
	encryptCmd.Flags().StringVarP(&outputName, "output", "o", "sensitive.txt.tdf", "name or path of output file; - for stdout")
	encryptCmd.Flags().BoolVar(&nanoFormat, "nano", false, "Output in nanoTDF format")
	encryptCmd.Flags().BoolVar(&noKIDInKAO, "no-kid-in-kao", false, "[deprecated] Disable storing key identifiers in TDF KAOs")
	encryptCmd.Flags().BoolVar(&nanoFormat, "nano", false, "Output in nanoTDF format")
	encryptCmd.Flags().StringVarP(&outputName, "output", "o", "sensitive.txt.tdf", "name or path of output file; - for stdout")
	encryptCmd.Flags().StringVarP(&joinedDataAttributes, "data-attributes", "a", "https://example.com/attr/attr1/value/value1", "space separated list of data attributes")

	ExamplesCmd.AddCommand(&encryptCmd)
}

func encrypt(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return cmd.Usage()
	}

	plainText := args[0]
	in := strings.NewReader(plainText)

	opts := []sdk.Option{
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	}

	if noKIDInKAO {
		opts = append(opts, sdk.WithNoKIDInKAO())
	}

	// Create new offline client
	client, err := sdk.New(platformEndpoint, opts...)
	if err != nil {
		return err
	}

	out := os.Stdout
	if outputName != "-" {
		out, err = os.Create(outputName)
		if err != nil {
			return err
		}
	}
	defer func() {
		if outputName != "-" {
			out.Close()
		}
	}()

	attributes := strings.Split(joinedDataAttributes, " ")

	if !nanoFormat {
		tdf, err := client.CreateTDF(out, in,
			sdk.WithDataAttributes(attributes...),
			sdk.WithKasInformation(
				sdk.KASInfo{
					// examples assume insecure http
					URL:       fmt.Sprintf("http://%s", platformEndpoint),
					PublicKey: "",
				}))
		if err != nil {
			return err
		}

		manifestJSON, err := json.MarshalIndent(tdf.Manifest(), "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(manifestJSON))
	} else {
		nanoTDFConfig, err := client.NewNanoTDFConfig()
		if err != nil {
			return err
		}
		nanoTDFConfig.SetAttributes(attributes)
		nanoTDFConfig.EnableECDSAPolicyBinding()
		err = nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", platformEndpoint))
		if err != nil {
			return err
		}

		_, err = client.CreateNanoTDF(out, in, *nanoTDFConfig)
		if err != nil {
			return err
		}

		if outputName != "-" {
			err = cat(cmd, outputName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func cat(cmd *cobra.Command, nTdfFile string) error {
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
