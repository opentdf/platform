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
		Use:   "benchmark-decision-v1-complex",
		Short: "benchmark authorization.GetDecisions with complex policy scenarios",
		Long: `A benchmark tool to measure authorization v1 performance with complex policies.
This benchmark exercises subject mapping evaluation with multiple attributes per resource.`,
		RunE: runDecisionBenchmarkV1Complex,
	}
	benchmarkCmd.Flags().IntVar(&complexAttrCount, "attrs", 5, "Number of attributes per resource")         //nolint:mnd // default shown in help
	benchmarkCmd.Flags().IntVar(&complexResourceCount, "resources", 100, "Number of resources per request") //nolint:mnd // default shown in help
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runDecisionBenchmarkV1Complex(_ *cobra.Command, _ []string) error {
	client, err := newSDK()
	if err != nil {
		return err
	}

	// Available attribute values from fixtures that have subject mappings
	availableAttrs := []string{
		"https://example.com/attr/attr1/value/value1",
		"https://example.com/attr/attr1/value/value2",
		"https://example.net/attr/attr1/value/value1",
		"https://example.com/attr/attr2/value/value1",
		"https://example.com/attr/attr2/value/value2",
	}

	// Build resource attributes with multiple attribute values each
	var ras []*authorization.ResourceAttribute
	for i := 0; i < complexResourceCount; i++ {
		var fqns []string
		for j := 0; j < complexAttrCount; j++ {
			fqns = append(fqns, availableAttrs[(i+j)%len(availableAttrs)])
		}
		ras = append(ras, &authorization.ResourceAttribute{AttributeValueFqns: fqns})
	}

	// Run benchmark iterations
	const iterations = 5
	var totalTime time.Duration
	var lastApproved, lastDenied int

	for iter := 0; iter < iterations; iter++ {
		start := time.Now()
		res, err := client.Authorization.GetDecisions(context.Background(), &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{{Value: &policy.Action_Standard{
						Standard: policy.Action_STANDARD_ACTION_DECRYPT,
					}}},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "complex-v1-entity-chain",
							Entities: []*authorization.Entity{
								{
									Id:         "jwtentity-0-clientid-opentdf-sdk",
									EntityType: &authorization.Entity_ClientId{ClientId: "opentdf-sdk"},
									Category:   authorization.Entity_CATEGORY_ENVIRONMENT,
								},
								{
									Id:         "jwtentity-1-username-sample-user",
									EntityType: &authorization.Entity_UserName{UserName: "sample-user"},
									Category:   authorization.Entity_CATEGORY_SUBJECT,
								},
							},
						},
					},
					ResourceAttributes: ras,
				},
			},
		})
		elapsed := time.Since(start)
		totalTime += elapsed

		if err != nil {
			return fmt.Errorf("iteration %d failed: %w", iter, err)
		}

		lastApproved = 0
		lastDenied = 0
		for _, dr := range res.GetDecisionResponses() {
			if dr.GetDecision() == authorization.DecisionResponse_DECISION_PERMIT {
				lastApproved++
			} else {
				lastDenied++
			}
		}
	}

	avgTime := totalTime / iterations
	decisionsPerSecond := float64(complexResourceCount) / avgTime.Seconds()

	// Print results
	fmt.Printf("# Complex Authorization v1 Benchmark Results\n\n")
	fmt.Printf("## Configuration\n")
	fmt.Printf("| Parameter              | Value                  |\n")
	fmt.Printf("|------------------------|------------------------|\n")
	fmt.Printf("| Resources per request  | %d                     |\n", complexResourceCount)
	fmt.Printf("| Attributes per resource | %d                    |\n", complexAttrCount)
	fmt.Printf("| Total attribute checks | %d                     |\n", complexResourceCount*complexAttrCount)
	fmt.Printf("| Iterations             | %d                     |\n", iterations)
	fmt.Printf("\n")
	fmt.Printf("## Results\n")
	fmt.Printf("| Metric                  | Value                  |\n")
	fmt.Printf("|-------------------------|------------------------|\n")
	fmt.Printf("| Approved Decisions      | %d                     |\n", lastApproved)
	fmt.Printf("| Denied Decisions        | %d                     |\n", lastDenied)
	fmt.Printf("| Average Request Time    | %s                     |\n", avgTime)
	fmt.Printf("| Decisions/second        | %.2f                   |\n", decisionsPerSecond)
	fmt.Printf("| Time per decision       | %s                     |\n", time.Duration(int64(avgTime)/int64(complexResourceCount)))

	return nil
}
