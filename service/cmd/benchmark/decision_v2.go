//nolint:forbidigo // The benchmark emits GitHub-flavored Markdown for CI summaries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"

	authzv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
)

func runDecisionV2(args []string) error {
	fs := flag.NewFlagSet("decision-v2", flag.ContinueOnError)
	var conn connectionConfig
	var count int
	addConnectionFlags(fs, &conn)
	fs.IntVar(&count, "count", defaultBenchmarkCount, "number of resources in the decision request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if count < 1 {
		return errors.New("count must be positive")
	}

	client, err := newClient(conn)
	if err != nil {
		return err
	}
	defer client.Close()

	resources := make([]*authzv2.Resource, 0, count)
	for i := range count {
		resources = append(resources, &authzv2.Resource{
			EphemeralId: "resource-" + strconv.Itoa(i),
			Resource: &authzv2.Resource_AttributeValues_{
				AttributeValues: &authzv2.Resource_AttributeValues{Fqns: []string{benchmarkAttribute}},
			},
		})
	}
	request := &authzv2.GetDecisionMultiResourceRequest{
		Action: &policy.Action{Name: "read"},
		EntityIdentifier: &authzv2.EntityIdentifier{Identifier: &authzv2.EntityIdentifier_EntityChain{
			EntityChain: &entity.EntityChain{
				EphemeralId: "benchmark-entity-chain",
				Entities: []*entity.Entity{
					{EphemeralId: "benchmark-client", EntityType: &entity.Entity_ClientId{ClientId: "cli-client"}, Category: entity.Entity_CATEGORY_ENVIRONMENT},
					{EphemeralId: "benchmark-user", EntityType: &entity.Entity_UserName{UserName: "sample-user"}, Category: entity.Entity_CATEGORY_SUBJECT},
				},
			},
		}},
		Resources: resources,
	}
	start := time.Now()
	response, err := client.AuthorizationV2.GetDecisionMultiResource(context.Background(), request)
	totalTime := time.Since(start)

	approved, denied := 0, 0
	if err == nil {
		for _, decision := range response.GetResourceDecisions() {
			if decision.GetDecision() == authzv2.Decision_DECISION_PERMIT {
				approved++
			} else {
				denied++
			}
		}
	}
	fmt.Println("## Authorization v2 Multi-Resource Decision Benchmark Results")
	fmt.Println("| Metric | Value |")
	fmt.Println("|---|---:|")
	fmt.Printf("| Approved Decision Requests | %d |\n", approved)
	fmt.Printf("| Denied Decision Requests | %d |\n", denied)
	fmt.Printf("| Total Time | %s |\n", totalTime)
	if err != nil {
		return fmt.Errorf("authorization v2 decision: %w", err)
	}
	if approved+denied != count {
		return fmt.Errorf("authorization v2 returned %d decisions for %d resources", approved+denied, count)
	}
	return nil
}
