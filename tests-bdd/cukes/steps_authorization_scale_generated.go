package cukes

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	scaleUsersKey       = "scale-users"
	scaleUnmapped       = "unmapped"
	scaleRead           = "read"
	scaleWrite          = "write"
	scaleResourceStream = 4
	scaleMaxFQNs        = 20
)

var (
	scaleClearances = []string{"critical", "high", "medium", "low"}
	scaleRegions    = []string{"region-a", "region-b", "region-c", "region-d", "region-e", "region-f", "region-g"}
)

type scaleUser struct {
	name      string
	projects  []int
	clearance int
	region    string
}

type scaleDocument struct {
	name      string
	projects  []int
	clearance int
	regions   []string
}

// A small directory represents entitlement sizes, not directory throughput.
// Independent subsets overlap naturally and span the whole attribute.
//
//nolint:mnd // fixture archetype sizes and independent random stream are defined here
func generateScaleUsers(values, seed int) []scaleUser {
	random := rand.New(rand.NewPCG(uint64(seed), 2)) //nolint:gosec // reproducible fixture
	users := []scaleUser{
		{name: "few-grants", clearance: 2, region: scaleRegions[0]},
		{name: "moderate-grants", clearance: 1, region: scaleRegions[1]},
		{name: "many-grants", clearance: 1, region: scaleRegions[2]},
		{name: "large-grants", clearance: 0, region: scaleRegions[3]},
		{name: "no-grants", clearance: 3, region: scaleRegions[4]},
	}
	for i, count := range []int{3, 10, 50, 500, 0} {
		users[i].projects = random.Perm(values)[:min(count, values)]
	}
	return users
}

func prepareScaleUsers(ctx context.Context, values, seed int) (context.Context, error) {
	if values < 500 || seed < 0 {
		return ctx, errors.New("scale users require at least 500 values and a nonnegative seed")
	}
	users := generateScaleUsers(values, seed)
	for _, user := range users {
		projects := make([]string, len(user.projects))
		for i, value := range user.projects {
			projects[i] = fmt.Sprintf("v%04d", value)
		}
		var err error
		_, err = registerLocalUser(ctx, user.name, user.name+"@example.com", map[string]any{
			"projects": projects, "clearance": []string{scaleClearances[user.clearance]}, "regions": []string{user.region},
		})
		if err != nil {
			return ctx, err
		}
		_, err = (&AuthorizationServiceStepDefinitions{}).thereIsASubjectEntityWithValueAndReferencedAs(ctx, "user_name", user.name, user.name)
		if err != nil {
			return ctx, err
		}
	}
	GetPlatformScenarioContext(ctx).RecordObject(scaleUsersKey, users)
	return ctx, nil
}

// The generated population follows the scale harness: 55% single-project,
// 40% 2-20 projects, and 5% deliberately over the 20-FQN boundary. Authorization
// traffic excludes over-limit documents, as the harness does. Add permitted
// examples for each user so sparse random intersections don't yield only denies.
//
//nolint:mnd // document proportions and ranges mirror the scale fixture described in the feature
func generateScaleDocuments(values, count, seed int, users []scaleUser) []scaleDocument {
	random := rand.New(rand.NewPCG(uint64(seed), 3)) //nolint:gosec // reproducible fixture
	documents := make([]scaleDocument, 0, count+100)
	for i := range count {
		projects := 1
		if i >= count*55/100 {
			projects = 2 + random.IntN(19)
		}
		if i >= count*95/100 {
			projects = 21 + random.IntN(10)
		}
		doc := scaleDocument{name: fmt.Sprintf("document-%04d", i), projects: random.Perm(values)[:projects], clearance: random.IntN(4)}
		for _, region := range random.Perm(len(scaleRegions))[:1+random.IntN(3)] {
			doc.regions = append(doc.regions, scaleRegions[region])
		}
		documents = append(documents, doc)
	}
	for _, user := range users {
		if len(user.projects) == 0 {
			continue
		}
		for i := range 25 {
			size := 1
			if i%2 != 0 {
				size = 2 + random.IntN(min(16, len(user.projects))-1)
			}
			projects := make([]int, size)
			for j, index := range random.Perm(len(user.projects))[:size] {
				projects[j] = user.projects[index]
			}
			documents = append(documents, scaleDocument{
				name: fmt.Sprintf("%s-permitted-%02d", user.name, i), projects: projects,
				clearance: user.clearance + random.IntN(4-user.clearance), regions: []string{user.region},
			})
		}
	}
	// A known value without a subject mapping tests fail-closed behavior.
	documents = append(documents, scaleDocument{name: scaleUnmapped, projects: []int{values}, clearance: 3, regions: slices.Clone(scaleRegions)})
	return documents
}

// Independent fixture oracle: all projects, sufficient clearance, and any region
// must match. Both configured actions grant access; other actions must deny.
func expectedScaleDocument(user scaleUser, doc scaleDocument, action string) authz.Decision {
	if action != scaleRead && action != scaleWrite {
		return authz.Decision_DECISION_DENY
	}
	if user.clearance > doc.clearance || !slices.Contains(doc.regions, user.region) {
		return authz.Decision_DECISION_DENY
	}
	for _, value := range doc.projects {
		if !slices.Contains(user.projects, value) {
			return authz.Decision_DECISION_DENY
		}
	}
	return authz.Decision_DECISION_PERMIT
}

func scaleDocumentFQNs(doc scaleDocument, attribute *policy.Attribute, classification, region *policy.Attribute) []string {
	fqns := make([]string, 0, len(doc.projects)+1+len(doc.regions))
	for _, value := range doc.projects {
		fqns = append(fqns, fmt.Sprintf("%s/value/v%04d", attribute.GetFqn(), value))
	}
	fqns = append(fqns, classification.GetFqn()+"/value/"+scaleClearances[doc.clearance])
	for _, value := range doc.regions {
		fqns = append(fqns, region.GetFqn()+"/value/"+value)
	}
	slices.Sort(fqns)
	return fqns
}

func buildGeneratedScaleCases(ctx context.Context, attributeRef string, count, seed int) ([]authorizationScaleCase, error) {
	scenario := GetPlatformScenarioContext(ctx)
	users, ok := scenario.GetObject(scaleUsersKey).([]scaleUser)
	if !ok {
		return nil, errors.New("scale users must be prepared before platform setup")
	}
	attribute, ok := scenario.GetObject(attributeRef).(*policy.Attribute)
	if !ok || len(attribute.GetValues()) < 501 {
		return nil, errors.New("missing large scale attribute")
	}
	classification, ok := scenario.GetObject("classification").(*policy.Attribute)
	if !ok {
		return nil, errors.New("missing classification attribute")
	}
	region, ok := scenario.GetObject("region").(*policy.Attribute)
	if !ok {
		return nil, errors.New("missing region attribute")
	}
	documents := generateScaleDocuments(len(attribute.GetValues())-1, count, seed, users)
	generated := len(documents)
	documents = slices.DeleteFunc(documents, func(doc scaleDocument) bool { return len(doc.projects)+1+len(doc.regions) > scaleMaxFQNs })
	scenario.RecordObject("scale-fixture-description", fmt.Sprintf("%d project values (allOf), 4 classification levels (hierarchy), 7 regions (anyOf); %d distinct subject mappings; %d resource mappings with 2-5 aliases; %d users holding 3/10/50/500/0 projects. %d eligible resource documents, %d over-limit documents excluded. Includes 100 permitted examples and one additional unmapped value. Both case and resource variant selection are seeded; case categories are sampled uniformly, not weighted as customer traffic.", len(attribute.GetValues())-1, len(attribute.GetValues())-1+len(scaleClearances)+len(scaleRegions), len(attribute.GetValues())-1, len(users), len(documents), generated-len(documents)))
	var cases []authorizationScaleCase
	groups := make(map[string]int)
	uniqueVariants := make(map[string]bool)
	for _, user := range users {
		chain, err := buildEntityChainFromIDs(scenario, user.name)
		if err != nil {
			return nil, err
		}
		for _, action := range []string{scaleRead, scaleWrite, "delete"} {
			add := func(category string, docs []scaleDocument) {
				request := &authz.GetDecisionMultiResourceRequest{
					EntityIdentifier: &authz.EntityIdentifier{Identifier: &authz.EntityIdentifier_EntityChain{EntityChain: chain}},
					Action:           &policy.Action{Name: action},
				}
				expected := make(map[string]authz.Decision)
				decisions := make([]string, len(docs))
				labels := make([]string, len(docs))
				for i, doc := range docs {
					id := fmt.Sprintf("resource%d", i)
					expected[id] = expectedScaleDocument(user, doc, action)
					decisions[i] = strings.TrimPrefix(expected[id].String(), "DECISION_")
					labels[i] = category + " pool"
					request.Resources = append(request.Resources, &authz.Resource{
						EphemeralId: id,
						Resource:    &authz.Resource_AttributeValues_{AttributeValues: &authz.Resource_AttributeValues{Fqns: scaleDocumentFQNs(doc, attribute, classification, region)}},
					})
				}
				name := strings.Join([]string{user.name, action, category, strings.Join(decisions, "/")}, " ")
				index, exists := groups[name]
				if !exists {
					index = len(cases)
					groups[name] = index
					cases = append(cases, authorizationScaleCase{name: name, entity: user.name, action: action, resources: labels, expected: expected})
				}
				var fingerprint strings.Builder
				fingerprint.WriteString(name)
				for _, resource := range request.GetResources() {
					fingerprint.WriteString("|")
					fingerprint.WriteString(strings.Join(resource.GetAttributeValues().GetFqns(), ","))
				}
				if key := fingerprint.String(); !uniqueVariants[key] {
					uniqueVariants[key] = true
					cases[index].variants = append(cases[index].variants, request)
				}
			}
			for _, doc := range documents {
				category := "single-project"
				if len(doc.projects) > 1 {
					category = "multi-project"
				}
				if doc.name == scaleUnmapped {
					category = scaleUnmapped
				}
				add(category, []scaleDocument{doc})
			}
			// Pair a user's permitted document with randomly selected documents. This
			// covers mixed decisions within one request as well as between requests.
			random := rand.New(rand.NewPCG(uint64(seed), scaleResourceStream)) //nolint:gosec // reproducible fixture
			for _, doc := range documents {
				if strings.HasPrefix(doc.name, user.name+"-permitted-") {
					add("three-resource", []scaleDocument{doc, documents[random.IntN(len(documents))], documents[random.IntN(len(documents))]})
				}
			}
		}
	}
	return cases, nil
}

func exerciseGeneratedAuthorizationLoad(ctx context.Context, requests, concurrency, seed int, requestTimeout, attributeRef string, documents int) (context.Context, error) {
	timeout, err := time.ParseDuration(requestTimeout)
	if err != nil || timeout <= 0 || concurrency < 1 || requests < concurrency || seed < 0 || documents < 100 {
		return ctx, errors.New("invalid generated load dimensions or timeout")
	}
	cases, err := buildGeneratedScaleCases(ctx, attributeRef, documents, seed)
	if err != nil {
		return ctx, err
	}
	return reportAuthorizationLoad(ctx, cases, requests, concurrency, seed, timeout)
}
