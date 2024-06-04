package cmd

import (
	"bytes"
	"fmt"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"io"
	"strconv"
	"strings"
	"time"
)

var nanoPerfCmd = &cobra.Command{
	Use:   "nano-perf [plaintext] [numNanoTDFs]",
	Short: "Measure nanoTDF performance",
	RunE:  nanoTdfPerf,
	Args:  cobra.MinimumNArgs(1),
}

func init() {
	ExamplesCmd.AddCommand(nanoPerfCmd)
}

func nanoTdfPerf(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}
	numNanoTDFs, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid number of NanoTDFs: %v", err)
	}

	strReader := strings.NewReader(plainText)

	// Create new offline client
	client, err := sdk.New(cmd.Context().Value(RootConfigKey).(*ExampleConfig).PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	)
	if err != nil {
		return err
	}

	//
	// NanoTDF
	//

	nanoTDFConfig, err := client.NewNanoTDFConfig()
	if err != nil {
		return err
	}

	nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", cmd.Flag("platformEndpoint").Value.String()))
	nanoTDFConfig.EnableECDSAPolicyBinding()

	nanoTDFArray := make([][]byte, numNanoTDFs)

	// Create NanoTDFs
	for i := 0; i < numNanoTDFs; i++ {
		strReader = strings.NewReader(plainText)
		var nTdfBuffer bytes.Buffer

		start := time.Now()
		_, err = client.CreateNanoTDF(&nTdfBuffer, strReader, *nanoTDFConfig)
		duration := time.Since(start)
		if err != nil {
			cmd.Println("CreateNanoTDF Failed")
			return err
		}

		nanoTDFArray[i] = nTdfBuffer.Bytes()
		cmd.Printf("NanoTDF %d created in %s\n", i, duration)
	}

	// Read NanoTDFs
	for i := 0; i < numNanoTDFs; i++ {
		var outBuf bytes.Buffer
		nTdfBuffer := bytes.NewReader(nanoTDFArray[i])

		start := time.Now()
		_, err = client.ReadNanoTDF(io.Writer(&outBuf), nTdfBuffer)
		duration := time.Since(start)
		if err != nil {
			cmd.Println("ReadNanoTDF Failed")
			return err
		}

		cmd.Printf("NanoTDF %d read in %s\n", i, duration)
	}

	cmd.Println("NanoTDFs created and read successfully")

	return nil
}
