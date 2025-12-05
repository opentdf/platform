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

var (
	complexAttrCount     int
	complexResourceCount int
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-decision-complex",
		Short: "benchmark authorization with complex policy scenarios",
		Long: `A benchmark tool to measure authorization performance with complex policies.
This benchmark exercises subject mapping evaluation with multiple attributes per resource
and multiple resources per request, showing where optimization improvements shine.`,
		RunE: runDecisionBenchmarkComplex,
	}
	benchmarkCmd.Flags().IntVar(&complexAttrCount, "attrs", 5, "Number of attributes per resource")         //nolint:mnd // default shown in help
	benchmarkCmd.Flags().IntVar(&complexResourceCount, "resources", 100, "Number of resources per request") //nolint:mnd // default shown in help
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runDecisionBenchmarkComplex(_ *cobra.Command, _ []string) error {
	client, err := newSDK()
	if err != nil {
		return err
	}

	// Available attribute values from fixtures that have subject mappings
	// These exercise different subject mapping conditions
	availableAttrs := []string{
		"https://example.com/attr/attr1/value/value1", // 4 subject mappings with complex AND/OR conditions
		"https://example.com/attr/attr1/value/value2", // 1 subject mapping
		"https://example.net/attr/attr1/value/value1", // 1 subject mapping with NOT_IN condition
		"https://example.com/attr/attr2/value/value1", // ALL_OF rule
		"https://example.com/attr/attr2/value/value2", // ALL_OF rule
	}

	// Build resources with multiple attributes each
	var resources []*authzV2.Resource
	for i := 0; i < complexResourceCount; i++ {
		// Select attributes for this resource (cycle through available ones)
		var fqns []string
		for j := 0; j < complexAttrCount; j++ {
			fqns = append(fqns, availableAttrs[(i+j)%len(availableAttrs)])
		}

		r := &authzV2.Resource{
			EphemeralId: "resource-" + strconv.Itoa(i),
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: fqns,
				},
			},
		}
		resources = append(resources, r)
	}

	// Run the benchmark multiple times to get stable measurements
	const iterations = 5
	var totalTime time.Duration
	var lastApproved, lastDenied int

	for iter := 0; iter < iterations; iter++ {
		start := time.Now()
		res, err := client.AuthorizationV2.GetDecisionMultiResource(context.Background(), &authzV2.GetDecisionMultiResourceRequest{
			Action: &policy.Action{
				Name: "read",
			},
			EntityIdentifier: &authzV2.EntityIdentifier{
				Identifier: &authzV2.EntityIdentifier_EntityChain{
					EntityChain: &entity.EntityChain{
						EphemeralId: "complex-benchmark-entity-chain",
						Entities: []*entity.Entity{
							{
								EphemeralId: "jwtentity-0-clientid-opentdf-sdk",
								EntityType:  &entity.Entity_ClientId{ClientId: "opentdf-sdk"},
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
		elapsed := time.Since(start)
		totalTime += elapsed

		if err != nil {
			return fmt.Errorf("iteration %d failed: %w", iter, err)
		}

		lastApproved = 0
		lastDenied = 0
		for _, decision := range res.GetResourceDecisions() {
			if decision.GetDecision() == authzV2.Decision_DECISION_PERMIT {
				lastApproved++
			} else {
				lastDenied++
			}
		}
	}

	avgTime := totalTime / iterations
	decisionsPerSecond := float64(complexResourceCount) / avgTime.Seconds()

	// Print results
	fmt.Printf("# Complex Authorization Benchmark Results\n\n")
	fmt.Printf("## Configuration\n")
	fmt.Printf("| Parameter            | Value                  |\n")
	fmt.Printf("|----------------------|------------------------|\n")
	fmt.Printf("| Resources per request | %d                    |\n", complexResourceCount)
	fmt.Printf("| Attributes per resource | %d                  |\n", complexAttrCount)
	fmt.Printf("| Total attribute checks | %d                   |\n", complexResourceCount*complexAttrCount)
	fmt.Printf("| Iterations           | %d                     |\n", iterations)
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
