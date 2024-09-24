package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	latitude, longitude float64
)

func init() {
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt TDF file",
		RunE:  decrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	decryptCmd.Flags().Float64Var(&latitude, "geo-lat", math.NaN(), "Geographic latitude")
	decryptCmd.Flags().Float64Var(&longitude, "geo-lng", math.NaN(), "Geographic longitude")
	ExamplesCmd.AddCommand(decryptCmd)
}

func decrypt(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	tdfFile := args[0]

	// Create new client
	client, err := newSDK()
	if err != nil {
		return err
	}
	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var magic [3]byte
	var isNano bool
	n, err := io.ReadFull(file, magic[:])
	switch {
	case err != nil:
		return err
	case n < 3:
		return errors.New("file too small; no magic number found")
	case bytes.HasPrefix(magic[:], []byte("L1L")):
		isNano = true
	default:
		isNano = false
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}

	if !isNano {
		opts := []sdk.TDFReaderOption{} // Define opts as an empty slice of Option
		if !math.IsNaN(latitude) || !math.IsNaN(longitude) {
			if math.IsNaN(latitude) || math.IsNaN(longitude) {
				return errors.New("both latitude and longitude must be provided")
			}
			opts = append(opts, sdk.WithLocationProvider(func() (string, error) {
				b, err := json.Marshal(map[string]float64{"lat": latitude, "lng": longitude})
				if err != nil {
					return "", err
				}
				return base64.StdEncoding.EncodeToString(b), nil
			}))
		}
		tdfreader, err := client.LoadTDF(file, opts...)
		if err != nil {
			return err
		}

		//Print decrypted string
		_, err = io.Copy(os.Stdout, tdfreader)
		if err != nil && err != io.EOF {
			return err
		}
	} else {
		_, err = client.ReadNanoTDF(os.Stdout, file)
		if err != nil {
			return err
		}
	}
	return nil
}
