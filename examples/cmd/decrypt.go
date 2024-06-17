package cmd

import (
	"bytes"
	"io"
	"os"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

func init() {
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt TDF file",
		RunE:  decrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	ExamplesCmd.AddCommand(decryptCmd)
}

func decrypt(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	tdfFile := args[0]

	// Create new client
	client, err := sdk.New(platformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
	)
	if err != nil {
		return err
	}
	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}

	defer file.Close()
	cmd.Println("# TDF")

	var isTDF = true
	tdfreader, err := client.LoadTDF(file)
	if err != nil {
		cmd.Println("Not TDF, proceeding to try Nano")
		isTDF = false
	}

	//Print TDF decrypted string
	if isTDF {
		_, err = io.Copy(os.Stdout, tdfreader)
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}

	cmd.Println("\n-----\n\n# NANO")

	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}
	outBuf := bytes.Buffer{}
	_, err = client.ReadNanoTDF(io.Writer(&outBuf), file)
	if err != nil {
		return err
	}

	if "Hello Virtru" == outBuf.String() {
		cmd.Println("✅ NanoTDF test passed!")
	} else {
		cmd.Println("❌ NanoTDF test failed!")
	}

	return nil
}
