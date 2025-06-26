//nolint:forbidigo // We use Println here extensively because we are printing markdown.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"time"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/spf13/cobra"
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-decision-v2",
		Short: "benchmark authorization.v2.GetDecisionMultiResource",
		Long:  `A OpenTDF benchmark tool to measure throughput and latency with configurable concurrency for authorization.v2.GetDecisionMultiResource.`,
		RunE:  runDecisionBenchmarkV2,
	}
	benchmarkCmd.Flags().IntVar(&config.RequestCount, "count", 100, "Total number of requests") //nolint: mnd // This is output to the help with explanation
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runDecisionBenchmarkV2(_ *cobra.Command, _ []string) error {
	// Create new offline client
	client, err := newSDK()
	if err != nil {
		return err
	}

	var resources []*authzV2.Resource
	attrValueFQN := "https://example.com/attr/attr1/value/value1"

	for i := range config.RequestCount {
		r := &authzV2.Resource{
			EphemeralId: "resource-%d" + strconv.Itoa(i),
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: []string{attrValueFQN},
				},
			},
		}
		resources = append(resources, r)
	}

	start := time.Now()
	res, err := client.AuthorizationV2.GetDecisionMultiResource(context.Background(), &authzV2.GetDecisionMultiResourceRequest{
		Action: &policy.Action{
			Name: "read",
		},
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{
				EntityChain: &entity.EntityChain{
					EphemeralId: "decision-bulk-entity-chain",
					Entities: []*entity.Entity{
						{
							EphemeralId: "jwtentity-0-clientid-opentdf-sdk",
							EntityType:  &entity.Entity_ClientId{ClientId: "cli-client"},
							Category:    entity.Entity_CATEGORY_ENVIRONMENT,
						},
						{
							EphemeralId: "jwtentity-1-username-sample-user",
							EntityType:  &entity.Entity_UserName{UserName: "sample-user"},
							Category:    entity.Entity_CATEGORY_SUBJECT,
						},
					},
				},
			},
		},
		Resources: resources,
	})
	end := time.Now()
	totalTime := end.Sub(start)

	numberApproved := 0
	numberDenied := 0
	if err == nil {
		for _, decision := range res.GetResourceDecisions() {
			if decision.GetDecision() == authzV2.Decision_DECISION_PERMIT {
				numberApproved++
			} else {
				numberDenied++
			}
		}
	}

	// Print results
	fmt.Printf("# Benchmark authorization.v2.GetMultiResourceDecision Results:\n")
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
