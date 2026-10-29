//nolint:forbidigo // The benchmark emits GitHub-flavored Markdown for CI summaries.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/opentdf/platform/sdk"
)

func runBulk(args []string) error {
	fs := flag.NewFlagSet("bulk", flag.ContinueOnError)
	var conn connectionConfig
	var count int
	addConnectionFlags(fs, &conn)
	fs.IntVar(&count, "count", defaultBenchmarkCount, "number of TDFs in the bulk decrypt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if count < 1 {
		return errors.New("count must be positive")
	}

	client, err := newClient(conn)
	if err != nil {
		return err
	}
	defer client.Close()
	path, err := createBenchmarkTDF(client, conn.endpoint)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	tdfs := make([]*sdk.BulkTDF, 0, count)
	for range count {
		tdfs = append(tdfs, &sdk.BulkTDF{Reader: bytes.NewReader(ciphertext), Writer: io.Discard})
	}
	start := time.Now()
	err = client.BulkDecrypt(context.Background(), sdk.WithTDFs(tdfs...), sdk.WithTDFType(sdk.Standard))
	totalTime := time.Since(start)

	bulkErrors := []error(nil)
	if err != nil {
		var ok bool
		bulkErrors, ok = sdk.FromBulkErrors(err)
		if !ok {
			bulkErrors = []error{err}
		}
	}
	failures := len(bulkErrors)
	if failures == 1 && err != nil {
		if _, ok := sdk.FromBulkErrors(err); !ok {
			failures = count
		}
	}
	successes := count - failures
	errorCounts := make(map[string]int)
	for _, bulkErr := range bulkErrors {
		errorCounts[bulkErr.Error()]++
	}

	fmt.Println("## Bulk Benchmark Results")
	fmt.Println("| Metric | Value |")
	fmt.Println("|---|---:|")
	fmt.Printf("| Total Decrypts | %d |\n", count)
	fmt.Printf("| Successful Decrypts | %d |\n", successes)
	fmt.Printf("| Failed Decrypts | %d |\n", failures)
	fmt.Printf("| Total Time | %s |\n", totalTime)
	fmt.Printf("| Throughput | %.2f requests/second |\n", float64(successes)/totalTime.Seconds())
	printErrorSummary(errorCounts)
	if err != nil {
		return fmt.Errorf("bulk decrypt failed: %w", err)
	}
	return nil
}
