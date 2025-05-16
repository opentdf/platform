package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/spf13/cobra"
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-decision",
		Short: "OpenTDF benchmark tool for GetDecisions",
		Long:  `A OpenTDF benchmark tool to measure GetDecisions throughput and latency.`,
		RunE:  runDecisionBenchmark,
	}
	benchmarkCmd.Flags().IntVar(&config.RequestCount, "count", 100, "Total number of *decision requests* within the GetDecisions call") // Clarify count
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runDecisionBenchmark(cmd *cobra.Command, args []string) error {
	client, err := newSDK()
	if err != nil {
		return fmt.Errorf("failed to create SDK client: %w", err)
	}

	// --- Prepare Request ---
	// This part might need adjustment based on how your policy expects resource attributes
	// For a meaningful benchmark, vary attributes or use realistic ones.
	// This example creates 'count' identical resource attributes, which might not
	// reflect real-world policy complexity well.
	fmt.Printf("Preparing %d resource attributes for the decision request...\n", config.RequestCount)
	ras := make([]*authorization.ResourceAttribute, 0, config.RequestCount)
	for i := 0; i < config.RequestCount; i++ {
		// Example: Varying attribute slightly per request might be more realistic
		// attrValue := fmt.Sprintf("https://example.com/attr/attr1/value/value%d", i % 10) // Example variation
		attrValue := "https://example.com/attr/attr1/value/value1" // Original example
		ras = append(ras, &authorization.ResourceAttribute{AttributeValueFqns: []string{attrValue}})
	}

	decisionRequestPayload := &authorization.GetDecisionsRequest{
		DecisionRequests: []*authorization.DecisionRequest{
			{
				Actions: []*policy.Action{{Value: &policy.Action_Standard{
					Standard: policy.Action_STANDARD_ACTION_DECRYPT,
				}}},
				EntityChains: []*authorization.EntityChain{
					{Id: "benchmark-entity-chain", Entities: []*authorization.Entity{ // Give it an ID
						{Id: "jwtentity-0-clientid-opentdf-public", EntityType: &authorization.Entity_ClientId{ClientId: "opentdf-public"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT},
						{Id: "jwtentity-1-username-sample-user", EntityType: &authorization.Entity_UserName{UserName: "sample-user"}, Category: authorization.Entity_CATEGORY_SUBJECT},
					}}},
				ResourceAttributes: ras,
			},
			// Add more DecisionRequests here if you want to test batching within GetDecisions
		},
	}

	fmt.Println("Starting decision benchmark...")
	start := time.Now()
	// --- Execute Benchmark ---
	res, err := client.Authorization.GetDecisions(context.Background(), decisionRequestPayload)
	end := time.Now()
	totalTime := end.Sub(start)
	totalTimeSeconds := totalTime.Seconds()

	// --- Process Results ---
	numberApproved := 0
	numberDenied := 0
	errMsg := ""
	if err != nil {
		errMsg = strings.ReplaceAll(err.Error(), "\n", " ") // Clean error message for output
		fmt.Printf("Error during GetDecisions: %v\n", err)
	} else if res == nil {
		errMsg = "GetDecisions returned nil response without error"
		fmt.Println(errMsg)
	} else {
		for _, dr := range res.GetDecisionResponses() {
			if dr.Decision == authorization.DecisionResponse_DECISION_PERMIT {
				numberApproved += 1
			} else {
				numberDenied += 1
			}
		}
	}
	totalDecisions := numberApproved + numberDenied
	decisionsPerSecond := 0.0
	if totalTimeSeconds > 0 && totalDecisions > 0 {
		decisionsPerSecond = float64(totalDecisions) / totalTimeSeconds
	}

	// --- Print Human-Readable Results ---
	fmt.Printf("\n# Benchmark Results (Human-Readable):\n")
	fmt.Printf("| Metric                  | Value                  |\n")
	fmt.Printf("|-------------------------|------------------------|\n")
	fmt.Printf("| Request Count           | %d                     |\n", config.RequestCount)
	fmt.Printf("| Total Decisions         | %d                     |\n", totalDecisions)
	if errMsg == "" {
		fmt.Printf("| Approved Decisions      | %d                     |\n", numberApproved)
		fmt.Printf("| Denied Decisions        | %d                     |\n", numberDenied)
	} else {
		fmt.Printf("| Error                   | %s |\n", errMsg)
	}
	fmt.Printf("| Total Time              | %s                   |\n", totalTime)
	fmt.Printf("| Decisions Per Second    | %.2f                 |\n", decisionsPerSecond)

	// --- Print Machine-Parseable Results (KEY PART) ---
	// Use a clear prefix like "BENCHMARK_METRIC:"
	fmt.Printf("\n# Machine-Parseable Metrics:\n")
	fmt.Printf("BENCHMARK_METRIC:TotalTimeSeconds:%.6f\n", totalTimeSeconds)
	fmt.Printf("BENCHMARK_METRIC:TotalDecisions:%d\n", totalDecisions)
	fmt.Printf("BENCHMARK_METRIC:ApprovedDecisions:%d\n", numberApproved)
	fmt.Printf("BENCHMARK_METRIC:DeniedDecisions:%d\n", numberDenied)
	fmt.Printf("BENCHMARK_METRIC:DecisionsPerSecond:%.4f\n", decisionsPerSecond)
	if errMsg != "" {
		fmt.Printf("BENCHMARK_METRIC:Error:%s\n", errMsg) // Capture errors too
	}

	// Return the original error, if any
	return err
}
