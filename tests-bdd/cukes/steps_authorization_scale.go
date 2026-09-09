package cukes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/proto"
)

const authorizationPerformanceMarker = "AUTHZ_PERFORMANCE "

type authorizationScaleCase struct {
	name     string
	entity   string
	action   string
	values   []string
	expected map[string]authz.Decision
}

type authorizationPerformanceResult struct {
	Case        string        `json:"case"`
	Seed        int           `json:"seed"`
	Concurrency int           `json:"concurrency"`
	Resources   int           `json:"resources"`
	Wall        time.Duration `json:"wall_ns"`
	Median      time.Duration `json:"median_ns"`
	P95         time.Duration `json:"p95_ns"`
	Maximum     time.Duration `json:"maximum_ns"`
	Timeout     time.Duration `json:"timeout_ns"`
	Failures    int           `json:"failures"`
	FirstError  string        `json:"first_error,omitempty"`
}

func parseAuthorizationScaleCases(table *godog.Table) ([]authorizationScaleCase, error) {
	headers := []string{"case", "entity", "action", valuesKey, "expected"}
	if table == nil || len(table.Rows) < 2 || len(table.Rows[0].Cells) != len(headers) {
		return nil, errors.New("authorization case table requires case, entity, action, values, expected columns")
	}
	for i, header := range headers {
		if table.Rows[0].Cells[i].Value != header {
			return nil, fmt.Errorf("expected column %q", header)
		}
	}
	cases := make([]authorizationScaleCase, 0, len(table.Rows)-1)
	names := make(map[string]bool)
	for _, row := range table.Rows[1:] {
		if len(row.Cells) != len(headers) {
			return nil, errors.New("authorization case row has incorrect column count")
		}
		item := authorizationScaleCase{
			name: strings.TrimSpace(row.Cells[0].Value), entity: strings.TrimSpace(row.Cells[1].Value),
			action: strings.TrimSpace(row.Cells[2].Value), values: strings.Split(row.Cells[3].Value, ","),
			expected: make(map[string]authz.Decision),
		}
		if item.name == "" || names[item.name] || item.entity == "" || item.action == "" {
			return nil, errors.New("cases require unique names, entities, and actions")
		}
		names[item.name] = true
		expected := strings.Split(row.Cells[4].Value, ",")
		if len(item.values) != len(expected) {
			return nil, fmt.Errorf("case %s has mismatched values and expectations", item.name)
		}
		for i, value := range item.values {
			item.values[i] = strings.TrimSpace(value)
			if item.values[i] == "" {
				return nil, fmt.Errorf("case %s has an empty value", item.name)
			}
			decision, ok := authz.Decision_value["DECISION_"+strings.TrimSpace(expected[i])]
			if !ok || (authz.Decision(decision) != authz.Decision_DECISION_PERMIT && authz.Decision(decision) != authz.Decision_DECISION_DENY) {
				return nil, fmt.Errorf("case %s requires explicit PERMIT or DENY expectations", item.name)
			}
			item.expected[fmt.Sprintf("resource%d", i)] = authz.Decision(decision)
		}
		cases = append(cases, item)
	}
	return cases, nil
}

func validateScaleDecision(response *authz.GetDecisionMultiResourceResponse, expected map[string]authz.Decision) error {
	if response == nil || len(response.GetResourceDecisions()) != len(expected) {
		return errors.New("unexpected resource decision count")
	}
	seen := make(map[string]bool, len(expected))
	for _, decision := range response.GetResourceDecisions() {
		id := decision.GetEphemeralResourceId()
		want, ok := expected[id]
		if !ok || seen[id] {
			return fmt.Errorf("unexpected or duplicate resource decision %q", id)
		}
		seen[id] = true
		if decision.GetDecision() != want {
			return fmt.Errorf("resource %s: expected %s, got %s", id, want, decision.GetDecision())
		}
		if len(decision.GetRequiredObligations()) != 0 {
			return fmt.Errorf("resource %s returned unexpected obligations", id)
		}
	}
	return nil
}

func exerciseAuthorizationCases(ctx context.Context, concurrency, seed int, requestTimeout, attributeRef string, table *godog.Table) (context.Context, error) {
	if concurrency < 1 || seed < 0 {
		return ctx, errors.New("concurrency must be positive and seed nonnegative")
	}
	timeout, err := time.ParseDuration(requestTimeout)
	if err != nil || timeout <= 0 {
		return ctx, fmt.Errorf("invalid duration %q", requestTimeout)
	}
	cases, err := parseAuthorizationScaleCases(table)
	if err != nil {
		return ctx, err
	}
	scenario := GetPlatformScenarioContext(ctx)
	attribute, ok := scenario.GetObject(attributeRef).(*policy.Attribute)
	if !ok || attribute.GetFqn() == "" {
		return ctx, fmt.Errorf("missing attribute %q", attributeRef)
	}
	// Shuffle all cases rather than sampling, so no expected path is omitted.
	random := rand.New(rand.NewPCG(uint64(seed), uint64(concurrency))) //nolint:gosec // reproducible test order, not security randomness
	random.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })
	var failures []error
	for _, item := range cases {
		chain, err := buildEntityChainFromIDs(scenario, item.entity)
		if err != nil {
			return ctx, err
		}
		request := &authz.GetDecisionMultiResourceRequest{
			EntityIdentifier: &authz.EntityIdentifier{Identifier: &authz.EntityIdentifier_EntityChain{EntityChain: chain}},
			Action:           &policy.Action{Name: item.action},
		}
		for i, value := range item.values {
			request.Resources = append(request.Resources, &authz.Resource{
				EphemeralId: fmt.Sprintf("resource%d", i),
				Resource: &authz.Resource_AttributeValues_{AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{attribute.GetFqn() + "/value/" + value},
				}},
			})
		}
		result, err := runAuthorizationScaleCase(ctx, scenario, item, request, concurrency, seed, timeout, random)
		encoded, encodeErr := json.Marshal(result)
		if encodeErr != nil {
			return ctx, encodeErr
		}
		// A structured record survives both console and Go test JSON output formats.
		fmt.Println(authorizationPerformanceMarker + string(encoded)) //nolint:forbidigo // structured CI record, independent of the configured log handler
		if err != nil {
			failures = append(failures, fmt.Errorf("case %s: %w", item.name, err))
		}
	}
	return ctx, errors.Join(failures...)
}

func runAuthorizationScaleCase(ctx context.Context, scenario *PlatformScenarioContext, item authorizationScaleCase, request *authz.GetDecisionMultiResourceRequest, concurrency, seed int, timeout time.Duration, random *rand.Rand) (authorizationPerformanceResult, error) {
	result := authorizationPerformanceResult{Case: item.name, Seed: seed, Concurrency: concurrency, Resources: len(item.values), Timeout: timeout}
	// Bound request completion without treating the timeout as a latency baseline.
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	requests := make([]*authz.GetDecisionMultiResourceRequest, concurrency)
	for i := range requests {
		requests[i] = proto.CloneOf(request)
		resources := requests[i].GetResources()
		random.Shuffle(len(resources), func(i, j int) { resources[i], resources[j] = resources[j], resources[i] })
	}
	durations := make([]time.Duration, concurrency)
	requestErrors := make([]error, concurrency)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range requests {
		workers.Go(func() {
			<-start
			started := time.Now()
			response, err := scenario.SDK.AuthorizationV2.GetDecisionMultiResource(requestCtx, requests[i])
			durations[i] = time.Since(started)
			if err == nil {
				err = validateScaleDecision(response, item.expected)
			}
			requestErrors[i] = err
		})
	}
	started := time.Now()
	close(start)
	workers.Wait()
	result.Wall = time.Since(started)
	for _, err := range requestErrors {
		if err != nil {
			result.Failures++
		}
	}
	slices.Sort(durations)
	result.Median = durations[(concurrency-1)/2]
	result.P95 = durations[(95*concurrency-1)/100]
	result.Maximum = durations[concurrency-1]
	var failure error
	for _, err := range requestErrors {
		if err != nil {
			failure = err
			result.FirstError = err.Error()
			break
		}
	}
	return result, failure
}
