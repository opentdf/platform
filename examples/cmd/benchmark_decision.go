//nolint:forbidigo // We use Println here extensively because we are printing markdown.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/spf13/cobra"
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-decision",
		Short: "OpenTDF benchmark tool",
		Long:  `A OpenTDF benchmark tool to measure throughput and latency with configurable concurrency.`,
		RunE:  runDecisionBenchmark,
	}
	benchmarkCmd.Flags().IntVar(&config.RequestCount, "count", 100, "Total number of requests") //nolint: mnd // This is output to the help with explanation
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runDecisionBenchmark(_ *cobra.Command, _ []string) error {
	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	ras := []*authorization.ResourceAttribute{}
	for i := 0; i < config.RequestCount; i++ {
		ras = append(ras, &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://example.com/attr/attr1/value/value1"}})
	}

	start := time.Now()
	res, err := client.Authorization.GetDecisions(context.Background(), &authorization.GetDecisionsRequest{
		DecisionRequests: []*authorization.DecisionRequest{
			{
				Actions: []*policy.Action{{Value: &policy.Action_Standard{
					Standard: policy.Action_STANDARD_ACTION_DECRYPT,
				}}},
				EntityChains: []*authorization.EntityChain{
					{Id: "rewrap-tok", Entities: []*authorization.Entity{
						{Id: "jwtentity-0-clientid-cli-client", EntityType: &authorization.Entity_ClientId{ClientId: "cli-client"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT},
						{Id: "jwtentity-1-username-sample-user", EntityType: &authorization.Entity_UserName{UserName: "sample-user"}, Category: authorization.Entity_CATEGORY_SUBJECT},
					}},
				},
				ResourceAttributes: ras,
			},
		},
	})
	end := time.Now()
	totalTime := end.Sub(start)

	numberApproved := 0
	numberDenied := 0
	if err == nil {
		for _, dr := range res.GetDecisionResponses() {
			if dr.GetDecision() == authorization.DecisionResponse_DECISION_PERMIT {
				numberApproved++
			} else {
				numberDenied++
			}
		}
	}

	// Print results
	fmt.Printf("# Benchmark authorization.GetDecisions Results:\n")
	fmt.Printf("| Metric                  | Value                  |\n")
	fmt.Printf("|-------------------------|------------------------|\n")
	if err == nil {
		fmt.Printf("| Approved Decision Requests | %d |\n", numberApproved)
		fmt.Printf("| Denied Decision Requests   | %d |\n", numberDenied)
	} else {
		fmt.Printf("| Error                    | %s |\n", err.Error())
	}
	fmt.Printf("| Total Time              | %s |\n", totalTime)

	return nil
}
