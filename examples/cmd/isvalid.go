package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func init() {
	encryptCmd := cobra.Command{
		Use:   "isvalid",
		Short: "Check validity of a TDF",
		RunE:  isValid,
		Args:  cobra.MinimumNArgs(1),
	}

	ExamplesCmd.AddCommand(&encryptCmd)
}

func isValid(cmd *cobra.Command, args []string) error {
	nanoTDFStr := "TDFMABJsb2NhbGhvc3Q6ODA4MC9rYXOAAQIA2qvjMRfg7b27lT2kf9SwHRkDIg8ZXtfRoiIvdMUHq/gL5AUMfmv4Di8sKCyLkmUm/WITVj5hDeV/z4JmQ0JL7ZxqSmgZoK6TAHvkKhUly4zMEWMRXH8IktKhFKy1+fD+3qwDopqWAO5Nm2nYQqi75atEFckstulpNKg3N+Ul22OHr/ZuR127oPObBDYNRfktBdzoZbEQcPlr8q1B57q6y5SPZFjEzL9weK+uS5bUJWkF3nsHASo2bZw7IPhTZxoFVmCDjwvj6MbxNa7zG6aClHJ162zKxLLnD9TtIHuZ59R7LgiSieipXeExj+ky9OgIw5DfwyUuxsQLtKpMIAFPmLY9Hy2naUJxke0MT1EUBgastCq+YtFGslV9LJo/A8FtrRqludwtM0O+Z9FlAkZ1oNL7M7uOkLrh7eRrv+C1AAAX6FaBQoOtqnmyu6Jp+VzkxDddEeLRUyI="
	// Decode the base64 string
	decodedData, err := base64.StdEncoding.DecodeString(nanoTDFStr)

	if len(args) != 1 {
		return cmd.Usage()
	}

	filePath := args[0]
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	isValidTdf, err := sdk.IsValidTdf(file)

	fmt.Println(err)

	in := bytes.NewReader(decodedData)
	isValidNanoTdf, err := sdk.IsValidNanoTdf(in)

	cmd.Println("Valid NanoTDF: ")
	cmd.Println(isValidNanoTdf)

	if err != nil {
		return err
	}
	cmd.Println("Valid TDF: ")
	cmd.Println(isValidTdf)
	_, err = in.Seek(0, io.SeekStart)
	tdfType := sdk.GetTdfType(in)
	cmd.Println("Type: ")
	cmd.Println(tdfType.String())

	return nil
}
