package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	autoconfigure  bool
	noKIDInKAO     bool
	outputName     string
	dataAttributes []string
	alg            string
)

func init() {
	encryptCmd := cobra.Command{
		Use:   "encrypt",
		Short: "Create encrypted TDF",
		RunE:  encrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	encryptCmd.Flags().StringSliceVarP(&dataAttributes, "data-attributes", "a", []string{"https://example.com/attr/attr1/value/value1"}, "space separated list of data attributes")
	encryptCmd.Flags().BoolVar(&autoconfigure, "autoconfigure", true, "Use attribute grants to select kases")
	encryptCmd.Flags().BoolVar(&noKIDInKAO, "no-kid-in-kao", false, "[deprecated] Disable storing key identifiers in TDF KAOs")
	encryptCmd.Flags().StringVarP(&outputName, "output", "o", "sensitive.txt.tdf", "name or path of output file; - for stdout")
	encryptCmd.Flags().StringVarP(&alg, "key-encapsulation-algorithm", "A", "rsa:2048", "Key wrap algorithm algorithm:parameters")

	ExamplesCmd.AddCommand(&encryptCmd)
}

func encrypt(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return cmd.Usage()
	}

	plainText := args[0]
	in := strings.NewReader(plainText)

	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	out := os.Stdout
	if outputName != "-" {
		out, err = os.Create(outputName)
		if err != nil {
			return err
		}
		defer out.Close()
	}

	baseKasURL := platformEndpoint
	if !strings.HasPrefix(baseKasURL, "http://") && !strings.HasPrefix(baseKasURL, "https://") {
		baseKasURL = "http://" + baseKasURL
	}

	opts := []sdk.TDFOption{sdk.WithDataAttributes(dataAttributes...)}
	if !autoconfigure {
		opts = append(opts, sdk.WithAutoconfigure(autoconfigure))
		opts = append(opts, sdk.WithKasInformation(
			sdk.KASInfo{
				URL:       baseKasURL,
				PublicKey: "",
			}))
	}
	if alg != "" {
		kt, err := keyTypeForKeyType(alg)
		if err != nil {
			return err
		}
		opts = append(opts, sdk.WithWrappingKeyAlg(kt)) //nolint:staticcheck // Example code still needs to set wrapping algorithm
	}
	tdf, err := client.CreateTDF(out, in, opts...)
	if err != nil {
		return err
	}

	manifestJSON, err := json.MarshalIndent(tdf.Manifest(), "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(manifestJSON))
	return nil
}

func keyTypeForKeyType(alg string) (ocrypto.KeyType, error) {
	switch alg {
	case string(ocrypto.RSA2048Key):
		return ocrypto.RSA2048Key, nil
	case string(ocrypto.EC256Key):
		return ocrypto.EC256Key, nil
	default:
		// do not submit add ocrypto.UnknownKey
		return ocrypto.RSA2048Key, fmt.Errorf("unsupported key type [%s]", alg)
	}
}
