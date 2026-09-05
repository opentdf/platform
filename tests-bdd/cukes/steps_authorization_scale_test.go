package cukes

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestScaleDecisionValidatesEachResourceRegardlessOfOrder(t *testing.T) {
	expected := map[string]authz.Decision{"resource0": authz.Decision_DECISION_PERMIT, "resource1": authz.Decision_DECISION_DENY}
	valid := &authz.GetDecisionMultiResourceResponse{ResourceDecisions: []*authz.ResourceDecision{
		{EphemeralResourceId: "resource1", Decision: authz.Decision_DECISION_DENY},
		{EphemeralResourceId: "resource0", Decision: authz.Decision_DECISION_PERMIT},
	}}
	require.NoError(t, validateScaleDecision(valid, expected))
	tests := []struct {
		name   string
		change func(*authz.GetDecisionMultiResourceResponse)
	}{
		{"incorrect deny", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[0].Decision = authz.Decision_DECISION_PERMIT
		}},
		{"duplicate resource", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[0].EphemeralResourceId = "resource0"
		}},
		{"unknown resource", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[0].EphemeralResourceId = "unknown"
		}},
		{"missing resource", func(r *authz.GetDecisionMultiResourceResponse) { r.ResourceDecisions = r.GetResourceDecisions()[:1] }},
		{"unexpected obligations", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[1].RequiredObligations = []string{"unexpected"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := proto.CloneOf(valid)
			tc.change(response)
			require.Error(t, validateScaleDecision(response, expected))
		})
	}
	require.Error(t, validateScaleDecision(nil, expected))
}

func TestScaleCasesRejectMissingTable(t *testing.T) {
	_, err := parseAuthorizationScaleCases(nil)
	require.Error(t, err)
}

func TestScaleLoadSamplesDifferentCasesReproducibly(t *testing.T) {
	selected := selectAuthorizationCases(24, 200, 4625)
	require.Equal(t, selected, selectAuthorizationCases(24, 200, 4625))
	require.NotEqual(t, selected, selectAuthorizationCases(24, 200, 4626))
	seen := make(map[int]bool)
	for _, index := range selected {
		require.Less(t, index, 24)
		require.GreaterOrEqual(t, index, 0)
		seen[index] = true
	}
	require.Len(t, seen, 24, "the checked-in seed should exercise the complete current case pool")
	require.Greater(t, len(slices.Compact(slices.Clone(selected))), 24, "cases must be interleaved rather than grouped into homogeneous batches")
}

func loadTestCase(name string) authorizationScaleCase {
	return authorizationScaleCase{
		name: name, entity: "test-user", action: "read", resources: []string{name},
		expected: map[string]authz.Decision{"resource0": authz.Decision_DECISION_PERMIT},
		request: &authz.GetDecisionMultiResourceRequest{Resources: []*authz.Resource{{
			EphemeralId: "resource0", Resource: &authz.Resource_AttributeValues_{AttributeValues: &authz.Resource_AttributeValues{Fqns: []string{name}}},
		}}},
	}
}

func permittedLoadResponse(request *authz.GetDecisionMultiResourceRequest) *authz.GetDecisionMultiResourceResponse {
	return &authz.GetDecisionMultiResourceResponse{ResourceDecisions: []*authz.ResourceDecision{{EphemeralResourceId: request.GetResources()[0].GetEphemeralId(), Decision: authz.Decision_DECISION_PERMIT}}}
}

func TestScaleLoadMixesRequestsAcrossBoundedWorkers(t *testing.T) {
	cases := []authorizationScaleCase{loadTestCase("engineering"), loadTestCase("projects"), loadTestCase("clearance")}
	const concurrency = 4
	started := make(chan string, concurrency)
	release := make(chan struct{})
	var calls, active, maximum atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type completion struct {
		result authorizationPerformanceResult
		err    error
	}
	done := make(chan completion, 1)
	go func() {
		result, err := runAuthorizationScaleLoad(ctx, cases, 40, concurrency, 4625, time.Second, func(ctx context.Context, request *authz.GetDecisionMultiResourceRequest) (*authz.GetDecisionMultiResourceResponse, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for previous := maximum.Load(); current > previous; previous = maximum.Load() {
				if maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			if calls.Add(1) <= concurrency {
				started <- request.GetResources()[0].GetAttributeValues().GetFqns()[0]
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return permittedLoadResponse(request), nil
		})
		done <- completion{result, err}
	}()
	first := make(map[string]bool)
	for range concurrency {
		select {
		case name := <-started:
			first[name] = true
		case <-ctx.Done():
			t.Fatal("workers did not start concurrently")
		}
	}
	close(release)
	finished := <-done
	require.NoError(t, finished.err)
	require.Greater(t, len(first), 1, "the same concurrent group should contain different cases")
	require.EqualValues(t, concurrency, maximum.Load())
	require.EqualValues(t, 40, calls.Load())
	require.Equal(t, 40, finished.result.Requests)
	total := 0
	for _, item := range finished.result.Cases {
		total += item.Requests
		require.Positive(t, item.Requests)
	}
	require.Equal(t, 40, total)
}

func TestScaleLoadUsesFreshDeadlineAndReportsFailure(t *testing.T) {
	calls := 0
	result, err := runAuthorizationScaleLoad(context.Background(), []authorizationScaleCase{loadTestCase("test")}, 2, 1, 4625, 10*time.Millisecond,
		func(ctx context.Context, request *authz.GetDecisionMultiResourceRequest) (*authz.GetDecisionMultiResourceResponse, error) {
			calls++
			if calls == 1 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return permittedLoadResponse(request), nil
		})
	require.Error(t, err)
	require.Equal(t, 2, calls)
	require.Equal(t, 1, result.Failures, "the second request must not inherit the first request's expired deadline")
	require.Equal(t, 1, result.Cases[0].Failures)
	require.Contains(t, result.Cases[0].FirstError, "deadline exceeded")
}

func TestScaleMappingRejectsMissingAction(t *testing.T) {
	require.NoError(t, validateScaleMappingActions([]*policy.Action{{Name: "write"}, {Name: "read"}}, "read,write"))
	require.ErrorContains(t, validateScaleMappingActions([]*policy.Action{{Name: "read"}}, "read,write"), "expected actions")
}
