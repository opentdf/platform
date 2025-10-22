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
	magicWord      string
	privateKeyPath string
)

func init() {
	encryptCmd := cobra.Command{
		Use:   "encrypt",
		Short: "Configure encrypted TDF",
		RunE:  encrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	encryptCmd.Flags().StringSliceVarP(&dataAttributes, "data-attributes", "a", []string{}, "space separated list of data attributes")
	encryptCmd.Flags().BoolVar(&nanoFormat, "nano", false, "Output in nanoTDF format")
	encryptCmd.Flags().BoolVar(&autoconfigure, "autoconfigure", true, "Use attribute grants to select kases")
	encryptCmd.Flags().BoolVar(&noKIDInKAO, "no-kid-in-kao", false, "[deprecated] Disable storing key identifiers in TDF KAOs")
	encryptCmd.Flags().BoolVar(&noKIDInNano, "no-kid-in-nano", true, "Disable storing key identifiers in nanoTDF KAS ResourceLocator")
	encryptCmd.Flags().StringVarP(&outputName, "output", "o", "sensitive.txt.tdf", "name or path of output file; - for stdout")
	encryptCmd.Flags().StringVarP(&alg, "key-encapsulation-algorithm", "A", "rsa:2048", "Key wrap algorithm algorithm:parameters")
	encryptCmd.Flags().IntVarP(&collection, "collection", "c", 0, "number of nano's to create for collection. If collection >0 (default) then output will be <iteration>_<output>")
	encryptCmd.Flags().StringVar(&policyMode, "policy-mode", "", "Store policy as encrypted instead of plaintext (nanoTDF only) [plaintext|encrypted]")
	encryptCmd.Flags().StringVar(&magicWord, "magic-word", "", "Magic word shared secret for assertion signing")
	encryptCmd.Flags().StringVar(&privateKeyPath, "private-key-path", "", "Path to private key file for assertion signing")
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
		autoconfigure = false
		if !autoconfigure {
			opts = append(opts, sdk.WithAutoconfigure(autoconfigure))
			opts = append(opts, sdk.WithKasInformation(
				sdk.KASInfo{
					URL:       baseKasURL,
					PublicKey: "",
				}))
		}
		// Deprecated: WithWrappingKeyAlg sets the key type for the TDF wrapping key for both storage and transit.
		if alg != "" {
			kt, err := keyTypeForKeyType(alg)
			if err != nil {
				return err
			}
			opts = append(opts, sdk.WithWrappingKeyAlg(kt))
		}
		// Magic word provider
		if magicWord != "" {
			// constructor with word works in a simple CLI
			magicWordProvider := NewMagicWordAssertionProvider(magicWord)
			opts = append(opts, sdk.WithAssertionBinder(magicWordProvider))
		}
		// Key provider
		if privateKeyPath != "" {
			privateKey, err := getAssertionKeyPrivate(privateKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load assertion key: %w", err)
			}
			publicKey, err := getAssertionKeyPublic(privateKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load public key: %w", err)
			}

			// Create statement value with public key information
			statement := struct {
				Algorithm string `json:"algorithm"`
				Key       any    `json:"key"`
			}{
				Algorithm: publicKey.Alg.String(),
				Key:       publicKey.Key,
			}
			statementJSON, err := json.Marshal(statement)
			if err != nil {
				return fmt.Errorf("failed to marshal statement: %w", err)
			}

			// useHex=false for modern TDF format (4.3.0+)
			publicKeyBinder := sdk.NewKeyAssertionBinder(privateKey, publicKey, string(statementJSON), false)
			opts = append(opts, sdk.WithAssertionBinder(publicKeyBinder))
		}
		// Add system metadata assertion (uses DEK)
		opts = append(opts, sdk.WithSystemMetadataAssertion())
		tdf, err := client.CreateTDFContext(cmd.Context(), out, in, opts...)
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
