package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var decryptOutputName string

func init() {
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt TDF file",
		RunE:  decrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	decryptCmd.Flags().StringVarP(&decryptOutputName, "output", "o", "-", "name or path of output file; - for stdout")
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

	out := os.Stdout
	if decryptOutputName != "-" {
		out, err = os.Create(decryptOutputName)
		if err != nil {
			return err
		}
	}
	defer func() {
		if decryptOutputName != "-" {
			out.Close()
		}
	}()

	if !isNano {
		tdfreader, err := client.LoadTDF(file)
		if err != nil {
			return err
		}

		//Print decrypted string
		_, err = io.Copy(out, tdfreader)
		if err != nil && err != io.EOF {
			return err
		}
	} else {
		_, err = client.ReadNanoTDF(out, file)
		if err != nil {
			return err
		}
	}
	return nil
}
