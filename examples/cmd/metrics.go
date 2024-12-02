package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

type Trace struct {
	Name      string `json:"Name"`
	StartTime string `json:"StartTime"`
	EndTime   string `json:"EndTime"`
}

type TraceStats struct {
	Count     int
	TotalTime int64 // nanoseconds
	MinTime   int64 // nanoseconds
	MaxTime   int64 // nanoseconds
}

const maxBufferSize = 64 * 1024 // 64KB buffer

var folderPath string

func init() {
	metricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "OpenTDF metrics tool",
		Long:  `An OpenTDF metrics tool to measure performance of opentdf services.`,
		RunE:  runMetrics,
	}

	metricsCmd.PersistentFlags().StringVarP(&folderPath, "folder", "f", "./traces", "Path to the folder containing traces.log")
	ExamplesCmd.AddCommand(metricsCmd)
}

func formatDuration(nanos int64) string {
	ms := float64(nanos) / 1_000_000.0 // Convert to milliseconds
	us := float64(nanos) / 1_000.0     // Convert to microseconds
	return fmt.Sprintf("%.3f ms (%.3f µs, %.0f ns)", ms, us, float64(nanos))
}

func runMetrics(cmd *cobra.Command, args []string) error {
	logFile := filepath.Join(folderPath, "traces.log")
	file, err := os.Open(logFile)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	traces := make(map[string]*TraceStats)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, maxBufferSize)
	scanner.Buffer(buf, maxBufferSize)

	for scanner.Scan() {
		line := scanner.Text()
		var trace Trace
		if err := json.Unmarshal([]byte(line), &trace); err != nil {
			cmd.Printf("Warning: Skipping malformed line: %v\n", err)
			continue
		}

		startTime, err := time.Parse(time.RFC3339Nano, trace.StartTime)
		if err != nil {
			cmd.Printf("Error parsing start time: %v\n", err)
			continue
		}

		endTime, err := time.Parse(time.RFC3339Nano, trace.EndTime)
		if err != nil {
			cmd.Printf("Error parsing end time: %v\n", err)
			continue
		}

		// Calculate duration in nanoseconds
		duration := endTime.UnixNano() - startTime.UnixNano()

		// Initialize trace stats if not exists
		if _, exists := traces[trace.Name]; !exists {
			traces[trace.Name] = &TraceStats{
				MinTime: duration,
				MaxTime: duration,
			}
		}

		// Update trace statistics
		stats := traces[trace.Name]
		stats.Count++
		stats.TotalTime += duration
		if duration < stats.MinTime {
			stats.MinTime = duration
		}
		if duration > stats.MaxTime {
			stats.MaxTime = duration
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Output statistics
	cmd.Println("\nTrace Statistics:")
	for name, stats := range traces {
		averageNanos := stats.TotalTime / int64(stats.Count)
		cmd.Printf("\n%s:\n", name)
		cmd.Printf("  Total Requests: %d\n", stats.Count)
		cmd.Printf("  Average Duration: %s\n", formatDuration(averageNanos))
		cmd.Printf("  Min Duration: %s\n", formatDuration(stats.MinTime))
		cmd.Printf("  Max Duration: %s\n", formatDuration(stats.MaxTime))
	}

	return nil
}
