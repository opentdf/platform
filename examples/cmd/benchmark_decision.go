package cmd

import (
	"context"
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

	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runDecisionBenchmark(cmd *cobra.Command, args []string) error {
	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	ras := []*authorization.ResourceAttribute{}
	for i := 0; i < 100; i++ {
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
						{Id: "jwtentity-0-clientid-opentdf-public", EntityType: &authorization.Entity_ClientId{ClientId: "opentdf-public"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT},
						{Id: "jwtentity-1-username-sample-user", EntityType: &authorization.Entity_UserName{UserName: "sample-user"}, Category: authorization.Entity_CATEGORY_SUBJECT},
					}}},
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
			if dr.Decision == authorization.DecisionResponse_DECISION_PERMIT {
				numberApproved += 1
			} else {
				numberDenied += 1
			}

		}
	}

	// Print results
	cmd.Printf("\nBenchmark Results:\n")
	if err == nil {
		cmd.Printf("Approved Decision Requests: %d\n", numberApproved)
		cmd.Printf("Denied Decision Requests: %d\n", numberDenied)
	} else {
		cmd.Printf("Error: %s\n", err.Error())
	}
	cmd.Printf("Total Time: %s\n", totalTime)

	return nil
}
