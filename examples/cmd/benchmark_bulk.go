//nolint:forbidigo,nestif // We use Println here extensively because we are printing markdown.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-bulk",
		Short: "OpenTDF benchmark tool",
		Long:  `A OpenTDF benchmark tool to measure Bulk Rewrap.`,
		RunE:  runBenchmarkBulk,
	}

	benchmarkCmd.Flags().IntVar(&config.RequestCount, "count", 100, "Total number of requests") //nolint: mnd // This is output to the help with explanation
	benchmarkCmd.Flags().Var(&config.TDFFormat, "tdf", "TDF format (tdf3 or nanotdf)")
benchmarkCmd.Flags().StringVar(&config.WrapperAlg, "wrapper", "rsa:2048", "Wrapper algorithm (e.g. rsa:2048, ec:secp256r1)")
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runBenchmarkBulk(cmd *cobra.Command, _ []string) error {
	in := strings.NewReader("Hello, World!")

	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	out := os.Stdout
	if outputName != "-" {
		out, err = os.Create("sensitive.txt.tdf")
		if err != nil {
			return err
		}
	}
	defer func() {
		if outputName != "-" {
			out.Close()
		}
	}()

	dataAttributes := []string{"https://example.com/attr/attr1/value/value1"}
	if config.TDFFormat == NanoTDF {
		nanoTDFConfig, err := client.NewNanoTDFConfig()
		if err != nil {
			return err
		}
		err = nanoTDFConfig.SetAttributes(dataAttributes)
		if err != nil {
			return err
		}
		nanoTDFConfig.EnableECDSAPolicyBinding()
		// if plaintext or platform endpoint is http, set kas url to http, otherwise https
		if insecurePlaintextConn || strings.HasPrefix(platformEndpoint, "http://") {
			err = nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", "localhost:8080"))
		} else {
			err = nanoTDFConfig.SetKasURL(fmt.Sprintf("https://%s/kas", "localhost:8080"))
		}
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
	} else {
		kt, err := keyTypeForKeyType(config.WrapperAlg)
		if err != nil {
			return fmt.Errorf("invalid wrapper algorithm: %w", err)
		}
		opts := []sdk.TDFOption{
			sdk.WithDataAttributes(dataAttributes...),
			sdk.WithAutoconfigure(false),
			sdk.WithWrappingKeyAlg(kt),
		}
		if insecurePlaintextConn || strings.HasPrefix(platformEndpoint, "http://") {
			opts = append(opts, sdk.WithKasInformation(
				sdk.KASInfo{
					URL:       "http://localhost:8080",
					PublicKey: "",
				}),
			)
		} else {
			opts = append(opts, sdk.WithKasInformation(
				sdk.KASInfo{
					URL:       "https://localhost:8080",
					PublicKey: "",
				}),
			)
		}
		tdf, err := client.CreateTDF(
			out, in,
			opts...,
		)
		if err != nil {
			return err
		}

		manifestJSON, err := json.MarshalIndent(tdf.Manifest(), "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(manifestJSON))
	}

	var errors []error
	var requestFailure error

	// Function to perform the operation
	operation := func() {
		file, err := os.Open("sensitive.txt.tdf")
		if err != nil {
			requestFailure = fmt.Errorf("file open error: %w", err)
			return
		}
		defer file.Close()
		cipher, _ := io.ReadAll(file)

		if _, err := file.Seek(0, 0); err != nil {
			requestFailure = fmt.Errorf("file seek error: %w", err)
		}

		format := sdk.Nano
		var bulkTdfs []*sdk.BulkTDF
		if config.TDFFormat == "tdf3" {
			format = sdk.Standard
		}
		for i := 0; i < config.RequestCount; i++ {
			bulkTdfs = append(bulkTdfs, &sdk.BulkTDF{Reader: bytes.NewReader(cipher), Writer: io.Discard})
		}
		err = client.BulkDecrypt(context.Background(), sdk.WithTDFs(bulkTdfs...), sdk.WithTDFType(format))
		if err != nil {
			if errList, ok := sdk.FromBulkErrors(err); ok {
				errors = errList
			} else {
				requestFailure = err
			}
		}
	}

	// Start the benchmark
	startTime := time.Now()
	operation()
	totalTime := time.Since(startTime)

	// Count errors and collect error messages
	var errorCount int
	successCount := 0
	if requestFailure != nil {
		errorCount = config.RequestCount
		errors = append(errors, requestFailure)
	} else {
		errorCount = len(errors)
		successCount = config.RequestCount - errorCount
	}
	throughput := float64(successCount) / totalTime.Seconds()

	errorMsgs := make(map[string]int)
	for _, err := range errors {
		errorMsgs[err.Error()]++
	}

	// Print results
	fmt.Printf("## Bulk Benchmark (%s, %s) Results\n", config.TDFFormat.String(), config.WrapperAlg)
	fmt.Printf("| Metric               | Value                     |\n")
	fmt.Printf("|----------------------|---------------------------|\n")
	fmt.Printf("| Total Decrypts       | %d                        |\n", config.RequestCount)
	fmt.Printf("| Successful Decrypts  | %d                        |\n", successCount)
	fmt.Printf("| Failed Decrypts      | %d                        |\n", errorCount)
	fmt.Printf("| Total Time           | %s                        |\n", totalTime)
	fmt.Printf("| Throughput           | %.2f requests/second      |\n", throughput)

	if errorCount > 0 {
		fmt.Printf("\n### Error Summary\n")
		fmt.Printf("| Error Message        | Occurrences               |\n")
		fmt.Printf("|----------------------|---------------------------|\n")
		for errMsg, count := range errorMsgs {
			fmt.Printf("| %s | %d occurrences           |\n", errMsg, count)
		}
	}

	return nil
}
