package cukes

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestScaleDirectEntitlementsCannotFallBackToSubjectMappingClaims(t *testing.T) {
	scenario := &PlatformScenarioContext{objects: make(map[string]any)}
	ctx := context.WithValue(t.Context(), platformScenarioContextKey{}, scenario)
	scenario.RecordObject(scaleUsersKey, []scaleUser{{name: "alice", projects: []int{2, 7}, clearance: 1, region: "region-b"}})
	scenario.RecordObject("projects", &policy.Attribute{Fqn: "https://scale.example/attr/project"})
	scenario.RecordObject("classification", &policy.Attribute{Fqn: "https://scale.example/attr/classification"})
	scenario.RecordObject("region", &policy.Attribute{Fqn: "https://scale.example/attr/region"})
	_, err := setScaleEntitlements(ctx, "direct-entitlement", "projects")
	require.NoError(t, err)
	user, ok := scenario.GetObject("alice").(*entity.Entity)
	require.True(t, ok)
	var claims structpb.Struct
	require.NoError(t, user.GetClaims().UnmarshalTo(&claims))
	require.Len(t, claims.GetFields(), 1, "mapping selectors must not have claims to match")
	grants, ok := claims.AsMap()[directEntitlementsClaimKey].([]any)
	require.True(t, ok)
	want := []string{
		"https://scale.example/attr/classification/value/high",
		"https://scale.example/attr/project/value/v0002",
		"https://scale.example/attr/project/value/v0007",
		"https://scale.example/attr/region/value/region-b",
	}
	require.Len(t, grants, len(want))
	for i, grant := range grants {
		got, grantOK := grant.(map[string]any)
		require.True(t, grantOK)
		require.Equal(t, want[i], got[directEntitlementColumnAttributeFQN])
		require.Equal(t, []any{"read", "write"}, got[directEntitlementColumnActions])
	}
}

func TestScaleDocumentExpectations(t *testing.T) {
	user := scaleUser{projects: []int{2, 7}, clearance: 1, region: scaleRegions[1]}
	tests := []struct {
		name      string
		projects  []int
		clearance int
		regions   []string
		action    string
		want      authz.Decision
	}{
		{"all projects and higher clearance", []int{2, 7}, 2, []string{"region-a", scaleRegions[1]}, "read", authz.Decision_DECISION_PERMIT},
		{"write and exact clearance", []int{7}, 1, []string{scaleRegions[1]}, "write", authz.Decision_DECISION_PERMIT},
		{"missing one project", []int{2, 8}, 2, []string{scaleRegions[1]}, "read", authz.Decision_DECISION_DENY},
		{"insufficient clearance", []int{2}, 0, []string{scaleRegions[1]}, "read", authz.Decision_DECISION_DENY},
		{"no matching region", []int{2}, 2, []string{"region-c"}, "read", authz.Decision_DECISION_DENY},
		{"ungranted action", []int{2}, 2, []string{scaleRegions[1]}, "delete", authz.Decision_DECISION_DENY},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, expectedScaleDocument(user, scaleDocument{projects: tc.projects, clearance: tc.clearance, regions: tc.regions}, tc.action))
		})
	}
}

func TestScaleFixtureDistributionAndDistinctConditions(t *testing.T) {
	users := generateScaleUsers(6000, 4625)
	require.Equal(t, users, generateScaleUsers(6000, 4625))
	require.NotEqual(t, users, generateScaleUsers(6000, 4626))
	for i, count := range []int{3, 10, 50, 500, 0} {
		require.Len(t, users[i].projects, count)
		for _, project := range users[i].projects {
			require.Less(t, project, 6000)
		}
	}
	docs := generateScaleDocuments(6000, 1000, 4625, users)
	require.Equal(t, docs, generateScaleDocuments(6000, 1000, 4625, users))
	require.Len(t, docs, 1101)
	single, multi, over := 0, 0, 0
	seen := map[int]bool{}
	for _, doc := range docs[:1000] {
		switch {
		case len(doc.projects) == 1:
			single++
		case len(doc.projects) <= 20:
			multi++
		default:
			over++
		}
		require.Len(t, slices.Compact(slices.Sorted(slices.Values(doc.projects))), len(doc.projects))
		for _, project := range doc.projects {
			seen[project] = true
		}
	}
	require.Equal(t, 550, single)
	require.Equal(t, 400, multi)
	require.Equal(t, 50, over)
	require.Greater(t, len(seen), 3000, "resource combinations must span the large policy")
	for _, doc := range docs[1000:1100] {
		for _, user := range users {
			if strings.HasPrefix(doc.name, user.name+"-permitted-") {
				require.Equal(t, authz.Decision_DECISION_PERMIT, expectedScaleDocument(user, doc, "read"))
			}
		}
	}
	for _, user := range users {
		require.Equal(t, authz.Decision_DECISION_DENY, expectedScaleDocument(user, docs[1100], "read"))
	}
	conditions := scaleValueConditions(".attributes.projects[]", []string{"v3000", "project-v3000"})
	group := conditions.GetSubjectSets()[0].GetConditionGroups()[0]
	require.Equal(t, policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR, group.GetBooleanOperator())
	require.Len(t, group.GetConditions(), 2)
	require.Equal(t, []string{"v3000", "project-v3000"}, group.GetConditions()[0].GetSubjectExternalValues())
	require.Equal(t, ".clientId", group.GetConditions()[1].GetSubjectExternalSelectorValue())
	require.Len(t, group.GetConditions()[1].GetSubjectExternalValues(), 4)
}

func TestGeneratedScaleCasesVaryRealResourcesAndKeepValidRequests(t *testing.T) {
	scenario := &PlatformScenarioContext{objects: make(map[string]any)}
	ctx := context.WithValue(t.Context(), platformScenarioContextKey{}, scenario)
	ctx, err := prepareScaleUsers(ctx, 6000, 4625)
	require.NoError(t, err)
	scenario.RecordObject("projects", &policy.Attribute{Fqn: "https://scale.example/attr/project", Values: make([]*policy.Value, 6001)})
	scenario.RecordObject("classification", &policy.Attribute{Fqn: "https://scale.example/attr/classification"})
	scenario.RecordObject("region", &policy.Attribute{Fqn: "https://scale.example/attr/region"})
	cases, err := buildGeneratedScaleCases(ctx, "projects", 1000, 4625)
	require.NoError(t, err)
	seen := map[string]bool{}
	mixed := false
	for _, item := range cases {
		require.NotEmpty(t, item.variants)
		unique := make(map[string]bool)
		for _, request := range item.variants {
			var signature strings.Builder
			require.Len(t, request.GetResources(), len(item.expected))
			for _, resource := range request.GetResources() {
				fqns := resource.GetAttributeValues().GetFqns()
				signature.WriteString("|")
				signature.WriteString(strings.Join(fqns, ","))
				require.LessOrEqual(t, len(fqns), 20)
				require.GreaterOrEqual(t, len(fqns), 3)
				for _, fqn := range fqns {
					seen[fqn] = true
				}
			}
			require.False(t, unique[signature.String()], "reported variants must contain different resource attributes")
			unique[signature.String()] = true
		}
		if item.expected["resource0"] == authz.Decision_DECISION_PERMIT && item.expected["resource1"] == authz.Decision_DECISION_DENY {
			mixed = true
		}
	}
	require.True(t, mixed, "multi-resource traffic must include different decisions in one request")
	require.Greater(t, len(seen), 2500, "eligible documents must still span thousands of values after excluding over-limit requests")
	selected := selectAuthorizationCases(len(cases), 200, 4625)
	selectedUsers, selectedActions := map[string]bool{}, map[string]bool{}
	for _, index := range selected {
		selectedUsers[cases[index].entity] = true
		selectedActions[cases[index].action] = true
	}
	require.Len(t, selectedUsers, 5)
	require.Len(t, selectedActions, 3)
	t.Logf("%d case categories, %d distinct FQNs in the resource pool", len(cases), len(seen))
}

func TestDynamicScaleRequestsUseUnprovisionedValues(t *testing.T) {
	scenario := &PlatformScenarioContext{objects: make(map[string]any)}
	ctx := context.WithValue(t.Context(), platformScenarioContextKey{}, scenario)
	ctx, err := prepareScaleUsers(ctx, 6000, 4625)
	require.NoError(t, err)
	scenario.RecordObject("projects", &policy.Attribute{Fqn: "https://scale.example/attr/project", Values: make([]*policy.Value, 6001)})
	scenario.RecordObject("classification", &policy.Attribute{Fqn: "https://scale.example/attr/classification"})
	scenario.RecordObject("region", &policy.Attribute{Fqn: "https://scale.example/attr/region"})
	scenario.RecordObject("scale-dynamic-projects", &policy.Attribute{Fqn: "https://scale.example/attr/project-dynamic"})
	cases, err := buildGeneratedScaleCases(ctx, "projects", 100, 4625)
	require.NoError(t, err)
	permitted, denied := false, false
	for _, item := range cases {
		for _, expected := range item.expected {
			permitted = permitted || expected == authz.Decision_DECISION_PERMIT
			denied = denied || expected == authz.Decision_DECISION_DENY
		}
		for _, request := range item.variants {
			for _, resource := range request.GetResources() {
				projects := 0
				for _, fqn := range resource.GetAttributeValues().GetFqns() {
					require.NotContains(t, fqn, "/attr/project/value/", "static subject mappings must not supply project grants")
					if strings.Contains(fqn, "/attr/project-dynamic/value/") {
						projects++
					}
				}
				require.Positive(t, projects, "each resource must exercise dynamic project resolution")
			}
		}
	}
	require.True(t, permitted)
	require.True(t, denied)
}

func TestScaleLoadSelectsResourceVariants(t *testing.T) {
	item := loadTestCase("generated")
	for i := range 50 {
		item.variants = append(item.variants, loadTestCase(fmt.Sprintf("document-%d", i)).request)
	}
	var previousRequests map[string]int
	for _, concurrency := range []int{1, 10, 25, 50} {
		sent := make(map[string]int)
		var lock sync.Mutex
		result, err := runAuthorizationScaleLoad(t.Context(), []authorizationScaleCase{item}, 200, concurrency, 4625, time.Second,
			func(_ context.Context, request *authz.GetDecisionMultiResourceRequest) (*authz.GetDecisionMultiResourceResponse, error) {
				fqn := request.GetResources()[0].GetAttributeValues().GetFqns()[0]
				lock.Lock()
				sent[fqn]++
				lock.Unlock()
				return permittedLoadResponse(request), nil
			})
		require.NoError(t, err)
		require.Greater(t, len(sent), 40, "workers must send distinct resource variants")
		require.Equal(t, len(sent), result.Cases[0].VariantsUsed, "reported variants must match actual requests")
		if previousRequests != nil {
			require.Equal(t, previousRequests, sent, "scheduling must not alter the request population")
		}
		previousRequests = sent
	}
}
