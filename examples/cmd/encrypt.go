//nolint:forbidigo,nestif // Sample code
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	nanoFormat     bool
	autoconfigure  bool
	noKIDInKAO     bool
	noKIDInNano    bool
	outputName     string
	dataAttributes []string
	collection     int
	alg            string
	policyMode     string
)

func init() {
	encryptCmd := cobra.Command{
		Use:   "encrypt",
		Short: "Create encrypted TDF",
		RunE:  encrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	encryptCmd.Flags().StringSliceVarP(&dataAttributes, "data-attributes", "a", []string{"https://example.com/attr/attr1/value/value1"}, "space separated list of data attributes")
	encryptCmd.Flags().BoolVar(&nanoFormat, "nano", false, "Output in nanoTDF format")
	encryptCmd.Flags().BoolVar(&autoconfigure, "autoconfigure", true, "Use attribute grants to select kases")
	encryptCmd.Flags().BoolVar(&noKIDInKAO, "no-kid-in-kao", false, "[deprecated] Disable storing key identifiers in TDF KAOs")
	encryptCmd.Flags().BoolVar(&noKIDInNano, "no-kid-in-nano", true, "Disable storing key identifiers in nanoTDF KAS ResourceLocator")
	encryptCmd.Flags().StringVarP(&outputName, "output", "o", "sensitive.txt.tdf", "name or path of output file; - for stdout")
	encryptCmd.Flags().StringVarP(&alg, "key-encapsulation-algorithm", "A", "rsa:2048", "Key wrap algorithm algorithm:parameters")
	encryptCmd.Flags().IntVarP(&collection, "collection", "c", 0, "number of nano's to create for collection. If collection >0 (default) then output will be <iteration>_<output>")
	encryptCmd.Flags().StringVar(&policyMode, "policy-mode", "", "Store policy as encrypted instead of plaintext (nanoTDF only) [plaintext|encrypted]")

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
	if outputName == "-" && collection > 0 {
		return errors.New("cannot use stdout for collection")
	}

	var writer []io.Writer
	if outputName == "-" {
		writer = append(writer, out)
	} else {
		dir, file := filepath.Split(outputName)
		for i := 0; i < collection; i++ {
			out, err = os.Create(filepath.Join(dir, fmt.Sprintf("%d_%s", i, file)))
			if err != nil {
				return err
			}
			writer = append(writer, out)
			defer out.Close()
		}
		if collection == 0 {
			out, err = os.Create(outputName)
			writer = append(writer, out)
			defer out.Close()
			if err != nil {
				return err
			}
		}
	}

	baseKasURL := platformEndpoint
	if !strings.HasPrefix(baseKasURL, "http://") && !strings.HasPrefix(baseKasURL, "https://") {
		baseKasURL = "http://" + baseKasURL
	}

	if !nanoFormat {
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
			opts = append(opts, sdk.WithWrappingKeyAlg(kt))
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
	} else {
		nanoTDFConfig, err := client.NewNanoTDFConfig()
		if err != nil {
			return err
		}
		err = nanoTDFConfig.SetAttributes(dataAttributes)
		if err != nil {
			return err
		}
		nanoTDFConfig.EnableECDSAPolicyBinding()
		if collection > 0 {
			nanoTDFConfig.EnableCollection()
		}
		err = nanoTDFConfig.SetKasURL(baseKasURL + "/kas")
		if err != nil {
			return err
		}

		// Handle policy mode if nanoTDF
		switch policyMode {
		case "": // default to encrypted
		case "encrypted":
			err = nanoTDFConfig.SetPolicyMode(sdk.NanoTDFPolicyModeEncrypted)
		case "plaintext":
			err = nanoTDFConfig.SetPolicyMode(sdk.NanoTDFPolicyModePlainText)
		default:
			err = fmt.Errorf("unsupported policy mode: %s", policyMode)
		}
		if err != nil {
			return err
		}

		for i, writer := range writer {
			input := plainText
			if collection > 0 {
				input = fmt.Sprintf("%d: %s", i, plainText)
			}
			in = strings.NewReader(input)
			_, err = client.CreateNanoTDF(writer, in, *nanoTDFConfig)
			if err != nil {
				return err
			}
		}

		if outputName != "-" && collection == 0 {
			err = cat(cmd, outputName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func keyTypeForKeyType(alg string) (ocrypto.KeyType, error) {
	kt := ocrypto.KeyType(alg)
	switch kt {
	case ocrypto.RSA2048Key, ocrypto.RSA4096Key, ocrypto.EC256Key, ocrypto.EC384Key, ocrypto.EC521Key:
		return kt, nil
	default:
return "", fmt.Errorf("unsupported key type [%s]", alg)
	}
}

func cat(_ *cobra.Command, nTdfFile string) error {
	f, err := os.Open(nTdfFile)
	if err != nil {
		return err
	}

	buf := bytes.Buffer{}
	_, err = buf.ReadFrom(f)
	if err != nil {
		return err
	}

	fmt.Println(string(ocrypto.Base64Encode(buf.Bytes())))

	return nil
}
