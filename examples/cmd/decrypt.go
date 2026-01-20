//nolint:forbidigo,nestif // Sample code
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opentdf/platform/sdk"

	"github.com/spf13/cobra"
)

func init() {
	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt TDF file",
		RunE:  decrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	decryptCmd.Flags().StringVarP(&alg, "rewrap-encapsulation-algorithm", "A", "rsa:2048", "Key wrap response algorithm algorithm:parameters")
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
	// Collection
	if stat, err := os.Stat(tdfFile); err == nil && stat.IsDir() {
		entries, err := os.ReadDir(tdfFile)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				f, err := os.Open(filepath.Join(tdfFile, entry.Name()))
				if err != nil {
					return err
				}
				opts := []sdk.TDFReaderOption{}
				if alg != "" {
					kt, err := keyTypeForKeyType(alg)
					if err != nil {
						return err
					}
					opts = append(opts, sdk.WithSessionKeyType(kt))
				}
				tdfReader, err := client.LoadTDF(f, opts...)
				if err != nil {
					return err
				}
				_, err = io.Copy(os.Stdout, tdfReader)
				if err != nil {
					return err
				}
				fmt.Println()
			}
		}
		client.Close()
		return nil
	}

	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}
	defer file.Close()

	opts := []sdk.TDFReaderOption{}
	if alg != "" {
		kt, err := keyTypeForKeyType(alg)
		if err != nil {
			return err
		}
		opts = append(opts, sdk.WithSessionKeyType(kt))
	}
	tdfReader, err := client.LoadTDF(file, opts...)
	if err != nil {
		return err
	}

	// Print decrypted string
	_, err = io.Copy(os.Stdout, tdfReader)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
