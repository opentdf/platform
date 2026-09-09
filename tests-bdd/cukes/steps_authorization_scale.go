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
	name, entity, action string
	resources            []string
	expected             map[string]authz.Decision
	request              *authz.GetDecisionMultiResourceRequest
}

type authorizationCaseResult struct {
	Name       string   `json:"name"`
	User       string   `json:"user"`
	Action     string   `json:"action"`
	Resources  []string `json:"resources"`
	Expected   []string `json:"expected"`
	Requests   int      `json:"requests"`
	Failures   int      `json:"failures"`
	FirstError string   `json:"first_error,omitempty"`
}

type authorizationPerformanceResult struct {
	Seed               int                       `json:"seed"`
	Concurrency        int                       `json:"concurrency"`
	Requests           int                       `json:"requests"`
	ResourcesRequested int                       `json:"resources_requested"`
	Wall               time.Duration             `json:"wall_ns"`
	Median             time.Duration             `json:"median_ns"`
	P95                time.Duration             `json:"p95_ns"`
	Maximum            time.Duration             `json:"maximum_ns"`
	Timeout            time.Duration             `json:"timeout_ns"`
	Failures           int                       `json:"failures"`
	Cases              []authorizationCaseResult `json:"cases"`
}

func scaleTableRows(table *godog.Table, headers ...string) ([][]string, error) {
	if table == nil || len(table.Rows) < 2 || len(table.Rows[0].Cells) != len(headers) {
		return nil, fmt.Errorf("table requires columns: %s", strings.Join(headers, ", "))
	}
	for i, header := range headers {
		if strings.TrimSpace(table.Rows[0].Cells[i].Value) != header {
			return nil, fmt.Errorf("expected column %q", header)
		}
	}
	rows := make([][]string, 0, len(table.Rows)-1)
	for _, row := range table.Rows[1:] {
		if len(row.Cells) != len(headers) {
			return nil, errors.New("incorrect table column count")
		}
		cells := make([]string, len(headers))
		for i, cell := range row.Cells {
			cells[i] = strings.TrimSpace(cell.Value)
			if cells[i] == "" {
				return nil, fmt.Errorf("empty %s cell", headers[i])
			}
		}
		rows = append(rows, cells)
	}
	return rows, nil
}

func parseAuthorizationScaleCases(table *godog.Table) ([]authorizationScaleCase, error) {
	rows, err := scaleTableRows(table, "case", "user", "action", "resources", "expected")
	if err != nil {
		return nil, err
	}
	cases := make([]authorizationScaleCase, 0, len(rows))
	names := make(map[string]bool)
	for _, row := range rows {
		item := authorizationScaleCase{name: row[0], entity: row[1], action: row[2], resources: strings.Split(row[3], ","), expected: make(map[string]authz.Decision)}
		if names[item.name] {
			return nil, fmt.Errorf("duplicate case %q", item.name)
		}
		names[item.name] = true
		expected := strings.Split(row[4], ",")
		if len(item.resources) != len(expected) {
			return nil, fmt.Errorf("case %s has mismatched resources and expectations", item.name)
		}
		for i, resource := range item.resources {
			item.resources[i] = strings.TrimSpace(resource)
			if item.resources[i] == "" {
				return nil, fmt.Errorf("case %s has an empty resource", item.name)
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

func exerciseAuthorizationLoad(ctx context.Context, requests, concurrency, seed int, requestTimeout string, table *godog.Table) (context.Context, error) {
	if concurrency < 1 || requests < concurrency || seed < 0 {
		return ctx, errors.New("requests must be at least concurrency, concurrency positive, and seed nonnegative")
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
	for i := range cases {
		item := &cases[i]
		chain, err := buildEntityChainFromIDs(scenario, item.entity)
		if err != nil {
			return ctx, err
		}
		item.request = &authz.GetDecisionMultiResourceRequest{
			EntityIdentifier: &authz.EntityIdentifier{Identifier: &authz.EntityIdentifier_EntityChain{EntityChain: chain}},
			Action:           &policy.Action{Name: item.action},
		}
		for i, name := range item.resources {
			fqns, ok := scenario.GetObject("scale-resource/" + name).([]string)
			if !ok || len(fqns) == 0 {
				return ctx, fmt.Errorf("case %s: missing resource %q", item.name, name)
			}
			item.request.Resources = append(item.request.Resources, &authz.Resource{
				EphemeralId: fmt.Sprintf("resource%d", i),
				Resource:    &authz.Resource_AttributeValues_{AttributeValues: &authz.Resource_AttributeValues{Fqns: fqns}},
			})
		}
	}
	result, runErr := runAuthorizationScaleLoad(ctx, cases, requests, concurrency, seed, timeout, scenario.SDK.AuthorizationV2.GetDecisionMultiResource)
	encoded, err := json.Marshal(result)
	if err != nil {
		return ctx, err
	}
	fmt.Println(authorizationPerformanceMarker + string(encoded)) //nolint:forbidigo // structured CI record, independent of the configured log handler
	return ctx, runErr
}

// Preselect uniformly with replacement so scheduling cannot change the workload.
// The same seed selects the same cases at every concurrency level.
func selectAuthorizationCases(caseCount, requests, seed int) []int {
	random := rand.New(rand.NewPCG(uint64(seed), 0)) //nolint:gosec // reproducible workload selection, not security randomness
	selected := make([]int, requests)
	for i := range selected {
		selected[i] = random.IntN(caseCount)
	}
	return selected
}

type scaleDecisionFunc func(context.Context, *authz.GetDecisionMultiResourceRequest) (*authz.GetDecisionMultiResourceResponse, error)

func runAuthorizationScaleLoad(ctx context.Context, cases []authorizationScaleCase, requests, concurrency, seed int, timeout time.Duration, decide scaleDecisionFunc) (authorizationPerformanceResult, error) {
	result := authorizationPerformanceResult{Seed: seed, Concurrency: concurrency, Requests: requests, Timeout: timeout, Cases: make([]authorizationCaseResult, len(cases))}
	selected := selectAuthorizationCases(len(cases), requests, seed)
	durations := make([]time.Duration, requests)
	requestErrors := make([]error, requests)
	jobs := make(chan int, requests)
	for i := range requests {
		jobs <- i
	}
	close(jobs)
	start := make(chan struct{})
	var workers, ready sync.WaitGroup
	ready.Add(concurrency)
	for range concurrency {
		workers.Go(func() {
			ready.Done()
			<-start
			for i := range jobs {
				item := cases[selected[i]]
				request := proto.CloneOf(item.request)
				// Each request gets a fresh deadline, including later work on the same worker.
				requestCtx, cancel := context.WithTimeout(ctx, timeout)
				started := time.Now()
				response, err := decide(requestCtx, request)
				durations[i] = time.Since(started)
				cancel()
				if err == nil {
					err = validateScaleDecision(response, item.expected)
				}
				requestErrors[i] = err
			}
		})
	}
	ready.Wait()
	started := time.Now()
	close(start)
	workers.Wait()
	result.Wall = time.Since(started)
	for i, item := range cases {
		row := authorizationCaseResult{Name: item.name, User: item.entity, Action: item.action, Resources: item.resources}
		for j := range item.resources {
			row.Expected = append(row.Expected, strings.TrimPrefix(item.expected[fmt.Sprintf("resource%d", j)].String(), "DECISION_"))
		}
		result.Cases[i] = row
	}
	var firstError error
	for i, caseIndex := range selected {
		row := &result.Cases[caseIndex]
		row.Requests++
		result.ResourcesRequested += len(row.Resources)
		if err := requestErrors[i]; err != nil {
			result.Failures++
			row.Failures++
			if row.FirstError == "" {
				row.FirstError = err.Error()
			}
			if firstError == nil {
				firstError = fmt.Errorf("case %s: %w", row.Name, err)
			}
		}
	}
	slices.Sort(durations)
	result.Median = durations[(requests-1)/2]
	result.P95 = durations[(95*requests-1)/100]
	result.Maximum = durations[requests-1]
	if firstError != nil {
		return result, fmt.Errorf("%d/%d authorization requests failed: %w", result.Failures, requests, firstError)
	}
	return result, nil
}
