//nolint:forbidigo // The benchmark emits GitHub-flavored Markdown for CI summaries.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

func runTDF(args []string) error {
	fs := flag.NewFlagSet("tdf", flag.ContinueOnError)
	var conn connectionConfig
	var count, concurrent int
	addConnectionFlags(fs, &conn)
	fs.IntVar(&count, "count", defaultBenchmarkCount, "total decrypt operations")
	fs.IntVar(&concurrent, "concurrent", defaultConcurrentCount, "maximum concurrent decrypt operations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if count < 1 || concurrent < 1 {
		return errors.New("count and concurrent must be positive")
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

	start := time.Now()
	jobs := make(chan struct{}, concurrent)
	durations := make(chan time.Duration, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		jobs <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-jobs }()
			operationStart := time.Now()
			file, err := os.Open(path)
			if err != nil {
				errs <- err
				return
			}
			defer file.Close()
			reader, err := client.LoadTDF(file)
			if err != nil {
				errs <- err
				return
			}
			if _, err := io.Copy(io.Discard, reader); err != nil && !errors.Is(err, io.EOF) {
				errs <- err
				return
			}
			durations <- time.Since(operationStart)
		}()
	}
	wg.Wait()
	close(durations)
	close(errs)

	totalTime := time.Since(start)
	var totalLatency time.Duration
	successes := 0
	for duration := range durations {
		totalLatency += duration
		successes++
	}
	errorCounts := make(map[string]int)
	for err := range errs {
		errorCounts[err.Error()]++
	}
	failures := count - successes

	fmt.Println("## TDF3 Benchmark Results")
	fmt.Println("| Metric | Value |")
	fmt.Println("|---|---:|")
	fmt.Printf("| Total Requests | %d |\n", count)
	fmt.Printf("| Successful Requests | %d |\n", successes)
	fmt.Printf("| Failed Requests | %d |\n", failures)
	fmt.Printf("| Concurrent Requests | %d |\n", concurrent)
	fmt.Printf("| Total Time | %s |\n", totalTime)
	if successes > 0 {
		fmt.Printf("| Average Latency | %s |\n", totalLatency/time.Duration(successes))
	}
	fmt.Printf("| Throughput | %.2f requests/second |\n", float64(successes)/totalTime.Seconds())
	printErrorSummary(errorCounts)
	if failures > 0 {
		return fmt.Errorf("%d of %d TDF decrypts failed", failures, count)
	}
	return nil
}

func printErrorSummary(errorCounts map[string]int) {
	if len(errorCounts) == 0 {
		return
	}
	fmt.Println("\n### Error Summary")
	fmt.Println("| Error Message | Occurrences |")
	fmt.Println("|---|---:|")
	for message, count := range errorCounts {
		fmt.Printf("| %s | %d |\n", gfmCellEscape(message), count)
	}
}
