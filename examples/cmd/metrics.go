package cmd

import (
	"bufio"
	"encoding/json"
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
	TotalTime float64
	MinTime   float64
	MaxTime   float64
}

type BatchStats struct {
	BatchCount int
	TotalTime  float64
	StartTime  time.Time
	EndTime    time.Time
}

var folderPath string
var batchCount int

func init() {
	metricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "OpenTDF metrics tool",
		Long:  `An OpenTDF metrics tool to measure performance of opentdf services.`,
		RunE:  runMetrics,
	}

	metricsCmd.PersistentFlags().StringVarP(&folderPath, "folder", "f", "./traces", "Path to the folder containing traces.log")
	metricsCmd.PersistentFlags().IntVarP(&batchCount, "batchcount", "b", 100, "Number of requests per batch")
	ExamplesCmd.AddCommand(metricsCmd)
}

func runMetrics(cmd *cobra.Command, args []string) error {
	logFilePath := filepath.Join(folderPath, "traces.log")
	file, err := os.Open(logFilePath)
	if err != nil {
		cmd.Println("Error opening file:", err)
		return err
	}
	defer file.Close()

	traces := make(map[string]*TraceStats)
	batchStats := make(map[string]*BatchStats)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var trace Trace
		err := json.Unmarshal(scanner.Bytes(), &trace)
		if err != nil {
			cmd.Println("Error parsing JSON:", err)
			continue
		}

		startTime, err := time.Parse(time.RFC3339Nano, trace.StartTime)
		if err != nil {
			cmd.Println("Error parsing start time:", err)
			continue
		}

		endTime, err := time.Parse(time.RFC3339Nano, trace.EndTime)
		if err != nil {
			cmd.Println("Error parsing end time:", err)
			continue
		}

		duration := endTime.Sub(startTime).Milliseconds()
		if _, exists := traces[trace.Name]; !exists {
			traces[trace.Name] = &TraceStats{
				MinTime: float64(duration),
				MaxTime: float64(duration),
			}
		}

		stats := traces[trace.Name]
		stats.Count++
		stats.TotalTime += float64(duration)
		if float64(duration) < stats.MinTime {
			stats.MinTime = float64(duration)
		}
		if float64(duration) > stats.MaxTime {
			stats.MaxTime = float64(duration)
		}

		if _, exists := batchStats[trace.Name]; !exists {
			batchStats[trace.Name] = &BatchStats{
				StartTime: startTime,
			}
		}

		batch := batchStats[trace.Name]
		batch.BatchCount++
		batch.TotalTime += float64(duration)
		batch.EndTime = endTime

		if batch.BatchCount == batchCount {
			average := batch.TotalTime / float64(batchCount)
			cmd.Printf("Name: %s, Batch Average Duration: %.2f ms, Start Time: %s, End Time: %s\n",
				trace.Name, average, batch.StartTime.Format(time.RFC3339), batch.EndTime.Format(time.RFC3339))
			batch.BatchCount = 0
			batch.TotalTime = 0
			batch.StartTime = endTime
		}
	}

	if err := scanner.Err(); err != nil {
		cmd.Println("Error reading file:", err)
	}

	for name, stats := range traces {
		average := stats.TotalTime / float64(stats.Count)
		cmd.Printf("Name: %s, Count: %d, Average Duration: %.2f ms, Min Duration: %.2f ms, Max Duration: %.2f ms\n",
			name, stats.Count, average, stats.MinTime, stats.MaxTime)
	}

	return nil
}
