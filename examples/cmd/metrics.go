package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	return fmt.Sprintf("%.3f ms", ms)
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
	fmt.Println("## Benchmark Statistics")
	fmt.Println("| Name | № Requests | Avg Duration | Min Duration | Max Duration |")
	fmt.Println("|------|------------|--------------|--------------|--------------|")

	// Sort trace names so output is visually consistent over time
	names := make([]string, 0, len(traces))
	for name := range traces {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		stats := traces[name]
		averageNanos := stats.TotalTime / int64(stats.Count)
		fmt.Printf("| %s | %d | %s | %s | %s |\n",
			name,
			stats.Count,
			formatDuration(averageNanos),
			formatDuration(stats.MinTime),
			formatDuration(stats.MaxTime),
		)
	}

	return nil
}
