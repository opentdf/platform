//nolint:forbidigo // We use fmt.Printf here extensively because we are printing markdown.
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

func gfmCellEscape(s string) string {
	// Escape pipe characters for GitHub Flavored Markdown tables
	pipes := strings.ReplaceAll(s, "|", "\\|")
	brs := strings.ReplaceAll(pipes, "\n", "<br>")
	return brs
}

type BenchmarkConfig struct {
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
	opts := []sdk.TDFOption{sdk.WithDataAttributes(dataAttributes...), sdk.WithAutoconfigure(false)}
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

	fmt.Printf("## %s Benchmark Results:\n", strings.ToUpper("tdf3"))
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
