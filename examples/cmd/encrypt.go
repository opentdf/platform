package cmd

import (
	"bytes"
	"encoding/json"
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
	encryptCmd.Flags().IntVarP(&collection, "collection", "c", 0, "number of nano's to create for collection. If collection >0 (default) then output will be <iteration>_<output>")

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
	}

	if noKIDInKAO {
		opts = append(opts, sdk.WithNoKIDInKAO())
	}
	// double negative always gets me
	if !noKIDInNano {
		opts = append(opts, sdk.WithNoKIDInNano())
	}

	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	out := os.Stdout
	if outputName == "-" && collection > 0 {
		return fmt.Errorf("cannot use stdout for collection")
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

	if !nanoFormat {
		opts := []sdk.TDFOption{sdk.WithDataAttributes(dataAttributes...)}
		if !autoconfigure {
			opts = append(opts, sdk.WithAutoconfigure(autoconfigure))
			opts = append(opts, sdk.WithKasInformation(
				sdk.KASInfo{
					// examples assume insecure http
					URL:       fmt.Sprintf("http://%s", platformEndpoint),
					PublicKey: "",
				}))
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
		nanoTDFConfig.SetAttributes(dataAttributes)
		nanoTDFConfig.EnableECDSAPolicyBinding()
		if collection > 0 {
			nanoTDFConfig.EnableCollection()
		}
		err = nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", platformEndpoint))
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
