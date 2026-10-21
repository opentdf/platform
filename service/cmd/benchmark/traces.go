//nolint:forbidigo // The benchmark emits GitHub-flavored Markdown for CI summaries.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type traceRecord struct {
	Name      string `json:"Name"`
	StartTime string `json:"StartTime"`
	EndTime   string `json:"EndTime"`
}

type traceStats struct {
	Count     int
	TotalTime time.Duration
	MinTime   time.Duration
	MaxTime   time.Duration
}

func runTraces(args []string) error {
	fs := flag.NewFlagSet("traces", flag.ContinueOnError)
	folder := fs.String("folder", "./traces", "folder containing traces.log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(*folder, "traces.log"))
	if err != nil {
		return err
	}
	defer file.Close()

	stats := make(map[string]*traceStats)
	decoder := json.NewDecoder(file)
	for {
		var trace traceRecord
		if err := decoder.Decode(&trace); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode trace record: %w", err)
		}
		start, err := time.Parse(time.RFC3339Nano, trace.StartTime)
		if err != nil {
			return fmt.Errorf("parse start time for %q: %w", trace.Name, err)
		}
		end, err := time.Parse(time.RFC3339Nano, trace.EndTime)
		if err != nil {
			return fmt.Errorf("parse end time for %q: %w", trace.Name, err)
		}
		duration := end.Sub(start)
		entry := stats[trace.Name]
		if entry == nil {
			entry = &traceStats{MinTime: duration, MaxTime: duration}
			stats[trace.Name] = entry
		}
		entry.Count++
		entry.TotalTime += duration
		entry.MinTime = min(entry.MinTime, duration)
		entry.MaxTime = max(entry.MaxTime, duration)
	}
	if len(stats) == 0 {
		return errors.New("trace log contained no records")
	}

	names := make([]string, 0, len(stats))
	for name := range stats {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Println("## Benchmark Trace Statistics")
	fmt.Println("| Name | Requests | Avg Duration | Min Duration | Max Duration |")
	fmt.Println("|---|---:|---:|---:|---:|")
	for _, name := range names {
		entry := stats[name]
		fmt.Printf("| %s | %d | %s | %s | %s |\n", gfmCellEscape(name), entry.Count, formatDuration(entry.TotalTime/time.Duration(entry.Count)), formatDuration(entry.MinTime), formatDuration(entry.MaxTime))
	}
	return nil
}

func formatDuration(duration time.Duration) string {
	return fmt.Sprintf("%.3f ms", float64(duration)/float64(time.Millisecond))
}
