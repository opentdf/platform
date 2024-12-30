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

	benchmarkCmd.Flags().IntVar(&config.ConcurrentRequests, "concurrent", 10, "Number of concurrent requests")
	benchmarkCmd.Flags().IntVar(&config.RequestCount, "count", 100, "Total number of requests")
	benchmarkCmd.Flags().IntVar(&config.RequestsPerSecond, "rps", 50, "Requests per second limit")
	benchmarkCmd.Flags().IntVar(&config.TimeoutSeconds, "timeout", 30, "Timeout in seconds")
	benchmarkCmd.Flags().Var(&config.TDFFormat, "tdf", "TDF format (tdf3 or nanotdf)")
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runBenchmark(cmd *cobra.Command, args []string) error {
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

	var dataAttributes = []string{"https://example.com/attr/attr1/value/value1"}
	if config.TDFFormat == NanoTDF {
		nanoTDFConfig, err := client.NewNanoTDFConfig()
		if err != nil {
			return err
		}
		nanoTDFConfig.SetAttributes(dataAttributes)
		nanoTDFConfig.EnableECDSAPolicyBinding()
		err = nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", "localhost:8080"))
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
		tdf, err :=
			client.CreateTDF(
				out, in,
				sdk.WithDataAttributes(dataAttributes...),
				sdk.WithKasInformation(
					sdk.KASInfo{
						URL:       fmt.Sprintf("http://%s", "localhost:8080"),
						PublicKey: "",
					}),
				sdk.WithAutoconfigure(false))
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
	requests := make(chan struct{}, config.ConcurrentRequests)
	results := make(chan time.Duration, config.RequestCount)
	errors := make(chan error, config.RequestCount)

	// Function to perform the operation
	operation := func() {
		defer wg.Done()
		start := time.Now()

		file, err := os.Open("sensitive.txt.tdf")
		if err != nil {
			errors <- fmt.Errorf("file open error: %v", err)
			return
		}
		defer file.Close()

		if config.TDFFormat == NanoTDF {
			_, err = client.ReadNanoTDF(io.Discard, file)
			if err != nil {
				errors <- fmt.Errorf("ReadNanoTDF error: %v", err)
				return
			}
		} else {
			tdfreader, err := client.LoadTDF(file)
			if err != nil {
				errors <- fmt.Errorf("LoadTDF error: %v", err)
				return
			}

			_, err = io.Copy(io.Discard, tdfreader)
			if err != nil && err != io.EOF {
				errors <- fmt.Errorf("read error: %v", err)
				return
			}
		}

		results <- time.Since(start)
	}

	// Start the benchmark
	startTime := time.Now()
	for i := 0; i < config.RequestCount; i++ {
		wg.Add(1)
		requests <- struct{}{}
		go func() {
			defer func() { <-requests }()
			operation()
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// Count errors and collect error messages
	errorCount := 0
	errorMsgs := make(map[string]int)
	for err := range errors {
		errorCount++
		errorMsgs[err.Error()]++
	}

	successCount := 0
	var totalDuration time.Duration
	for result := range results {
		successCount++
		totalDuration += result
	}
	if successCount == 0 {
		if errorCount > 0 {
			cmd.Printf("\nError Summary:\n")
			for errMsg, count := range errorMsgs {
				cmd.Printf("%s: %d occurrences\n", errMsg, count)
			}
		}
		return fmt.Errorf("no successful requests")
	}

	totalTime := time.Since(startTime)
	averageLatency := totalDuration / time.Duration(successCount)
	throughput := float64(successCount) / totalTime.Seconds()

	// Print results
	cmd.Printf("\nBenchmark Results:\n")
	cmd.Printf("Total Requests: %d\n", config.RequestCount)
	cmd.Printf("Successful Requests: %d\n", successCount)
	cmd.Printf("Failed Requests: %d\n", errorCount)
	cmd.Printf("Concurrent Requests: %d\n", config.ConcurrentRequests)
	cmd.Printf("Total Time: %s\n", totalTime)
	cmd.Printf("Average Latency: %s\n", averageLatency)
	cmd.Printf("Throughput: %.2f requests/second\n", throughput)

	if errorCount > 0 {
		cmd.Printf("\nError Summary:\n")
		for errMsg, count := range errorMsgs {
			cmd.Printf("%s: %d occurrences\n", errMsg, count)
		}
	}

	return nil
}
