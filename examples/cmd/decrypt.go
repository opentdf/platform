//nolint:forbidigo,nestif // Sample code
package cmd

import (
	"bytes"
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
				_, err = client.ReadNanoTDF(os.Stdout, f)
				fmt.Println()
				if err != nil {
					return err
				}
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

	var magic [3]byte
	var isNano bool
	n, err := io.ReadFull(file, magic[:])
	switch {
	case err != nil:
		return err
	case n < 3: //nolint: mnd // All TDFs are more than 2 bytes
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
		opts := []sdk.TDFReaderOption{}
		if alg != "" {
			kt, err := keyTypeForKeyType(alg)
			if err != nil {
				return err
			}
			opts = append(opts, sdk.WithSessionKeyType(kt))
		}
		tdfreader, err := client.LoadTDF(file, opts...)
		if err != nil {
			return err
		}

		// Print decrypted string
		_, err = io.Copy(os.Stdout, tdfreader)
		if err != nil && !errors.Is(err, io.EOF) {
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
