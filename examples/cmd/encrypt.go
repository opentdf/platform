package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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
	region         string
	geotdfPrefix   string
	dataAttributes []string
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
	encryptCmd.Flags().StringVar(&region, "geo-region", "", "region for geoTDF encoding, if desired. e.g. --region=office")
	encryptCmd.Flags().StringVar(&geotdfPrefix, "geo-prefix", "https://demo.com/attr/geospatial/value/WITHIN::", "FQN prefix for geofencing data attributes")

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

	if !nanoFormat {
		if region != "" {
			a, err := regionToDataAttribute(region)
			if err != nil {
				return err
			}
			dataAttributes = append(dataAttributes, a)
		}
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

type Location struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

func regionToDataAttribute(region string) (string, error) {
	// Implement the function to return a data attribute based on the region
	var l []Location
	switch region {
	default:
		return "", fmt.Errorf("unknown region: %s", region)
	case "office":
		l = []Location{
			{38.90034854189383, -77.04212675686254},
			{38.90034852050663, -77.04186123377212},
			{38.900838220852215, -77.04185361148076},
			{38.90086633875238, -77.04223651735694},
		}
	}
	rs, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	return geotdfPrefix + base64.StdEncoding.EncodeToString(rs), nil
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
