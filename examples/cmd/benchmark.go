//nolint:forbidigo,nestif // We use Println here extensively because we are printing markdown.
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

type TDFFormat string

const (
	TDF3    TDFFormat = "tdf3"
	NanoTDF TDFFormat = "nanotdf"
)

func gfmCellEscape(s string) string {
	// Escape pipe characters for GitHub Flavored Markdown tables
	pipes := strings.ReplaceAll(s, "|", "\\|")
	brs := strings.ReplaceAll(pipes, "\n", "<br>")
	return brs
}

func (f *TDFFormat) String() string {
	return string(*f)
}

func (f *TDFFormat) Set(value string) error {
	switch value {
	case "tdf3", "nanotdf":
		*f = TDFFormat(value)
		return nil
	default:
		return errors.New("invalid TDF format")
	}
}

func (f *TDFFormat) Type() string {
	return "TDFFormat"
}

type BenchmarkConfig struct {
	TDFFormat          TDFFormat
	WrapperAlg         string
	ConcurrentRequests int
	RequestCount       int
	RequestsPerSecond  int
	TimeoutSeconds     int
}

var config BenchmarkConfig

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark",
		Short: "OpenTDF benchmark tool",
		Long:  `A OpenTDF benchmark tool to measure throughput and latency with configurable concurrency.`,
		RunE:  runBenchmark,
	}

	benchmarkCmd.Flags().IntVar(&config.ConcurrentRequests, "concurrent", 10, "Number of concurrent requests") //nolint: mnd // This is output to the help with explanation
	benchmarkCmd.Flags().IntVar(&config.RequestCount, "count", 100, "Total number of requests")                //nolint: mnd // This is output to the help with explanation
	benchmarkCmd.Flags().IntVar(&config.RequestsPerSecond, "rps", 50, "Requests per second limit")             //nolint: mnd // This is output to the help with explanation
	benchmarkCmd.Flags().IntVar(&config.TimeoutSeconds, "timeout", 30, "Timeout in seconds")                   //nolint: mnd // This is output to the help with explanation
	benchmarkCmd.Flags().Var(&config.TDFFormat, "tdf", "TDF format (tdf3 or nanotdf)")
benchmarkCmd.Flags().StringVar(&config.WrapperAlg, "wrapper", "rsa:2048", "Wrapper algorithm (e.g. rsa:2048, ec:secp256r1)")
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runBenchmark(cmd *cobra.Command, _ []string) error {
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

		// if outputName != "-" {
		// 	err = cat(cmd, outputName)
		// 	if err != nil {
		// 		return err
		// 	}
		// }
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

	var wg sync.WaitGroup
	// Queries (requests) channel
	q := make(chan struct{}, config.ConcurrentRequests)
	// Answer (response) channel
	a := make(chan time.Duration, config.RequestCount)
	// Error channel
	e := make(chan error, config.RequestCount)

	// Function to perform the operation
	operation := func() {
		defer wg.Done()
		start := time.Now()

		file, err := os.Open("sensitive.txt.tdf")
		if err != nil {
			e <- fmt.Errorf("file open error: %w", err)
			return
		}
		defer file.Close()

		if config.TDFFormat == NanoTDF {
			_, err = client.ReadNanoTDF(io.Discard, file)
			if err != nil {
				e <- fmt.Errorf("ReadNanoTDF error: %w", err)
				return
			}
		} else {
			tdfreader, err := client.LoadTDF(file)
			if err != nil {
				e <- fmt.Errorf("LoadTDF error: %w", err)
				return
			}

			_, err = io.Copy(io.Discard, tdfreader)
			if err != nil && !errors.Is(err, io.EOF) {
				e <- fmt.Errorf("read error: %w", err)
				return
			}
		}

		a <- time.Since(start)
	}

	// Start the benchmark
	startTime := time.Now()
	for i := 0; i < config.RequestCount; i++ {
		wg.Add(1)
		q <- struct{}{}
		go func() {
			defer func() { <-q }()
			operation()
		}()
	}

	wg.Wait()
	close(a)
	close(e)

	// Count errors and collect error messages
	errorCount := 0
	errorMsgs := make(map[string]int)
	for err := range e {
		errorCount++
		errorMsgs[err.Error()]++
	}

	successCount := 0
	var totalDuration time.Duration
	for result := range a {
		successCount++
		totalDuration += result
	}

	totalTime := time.Since(startTime)
	var averageLatency time.Duration
	if successCount > 0 {
		averageLatency = totalDuration / time.Duration(successCount)
	}
	throughput := float64(successCount) / totalTime.Seconds()

	format := config.TDFFormat
	if format == "" {
		format = TDF3
	}
	fmt.Printf("## %s (%s) Benchmark Results:\n", strings.ToUpper(format.String()), config.WrapperAlg)
	fmt.Printf("| Metric                | Value                     |\n")
	fmt.Printf("|-----------------------|---------------------------|\n")
	fmt.Printf("| Total Requests        | %d                        |\n", config.RequestCount)
	fmt.Printf("| Successful Requests   | %d                        |\n", successCount)
	fmt.Printf("| Failed Requests       | %d                        |\n", errorCount)
	fmt.Printf("| Concurrent Requests   | %d                        |\n", config.ConcurrentRequests)
	fmt.Printf("| Total Time            | %s                        |\n", totalTime)
	if successCount > 0 {
		fmt.Printf("| Average Latency       | %s                        |\n", averageLatency)
	}
	fmt.Printf("| Throughput            | %.2f requests/second      |\n", throughput)

	if errorCount > 0 {
		fmt.Printf("\n### Error Summary:\n")
		fmt.Printf("| Error Message         | Occurrences              |\n")
		fmt.Printf("|-----------------------|---------------------------|\n")
		for errMsg, count := range errorMsgs {
			fmt.Printf("| %s | %d occurrences         |\n", gfmCellEscape(errMsg), count)
		}
	}
	return nil
}
