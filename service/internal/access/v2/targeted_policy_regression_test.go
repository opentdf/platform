package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/common"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func regressionSDK(f *targetedPolicyFixture, rr *fakeRegisteredResourcesClient) *otdfSDK.SDK {
	return &otdfSDK.SDK{
		Attributes: f.attributesClient(), RegisteredResources: rr,
		Obligations: &fakeObligationsClient{triggers: f.triggers},
		EntityResolutionV2: &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
			EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
		}},
	}
}

func regressionDecision(ctx context.Context, t *testing.T, f *targetedPolicyFixture, rr *fakeRegisteredResourcesClient, cached, strict bool, entity *authzV2.EntityIdentifier, action *policy.Action, resources []*authzV2.Resource) *Decision {
	t.Helper()
	var store EntitlementPolicyStore = &decisionPolicyStore{}
	if cached {
		store = fullPolicyStore{fixture: f}
	}
	pdp, err := NewJustInTimePDP(ctx, logger.CreateTestLogger(), regressionSDK(f, rr), store, false, false, strict)
	require.NoError(t, err)
	decision, err := pdp.GetDecision(ctx, entity, action, resources, nil, []string{fixtureWatermark})
	require.NoError(t, err)
	return sortedDecision(decision)
}

func TestJITPDP_TargetedNamespacedActions(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, scopedAction := range []bool{false, true} {
			f := newTargetedPolicyFixture()
			ns := &policy.Namespace{Id: "example-id", Name: "example.com", Fqn: "https://example.com"}
			for _, definition := range f.definitions {
				definition.Namespace = ns
			}
			for _, mappings := range f.subjectMappings {
				for _, mapping := range mappings {
					mapping.Namespace = ns
					for _, action := range mapping.GetActions() {
						action.Namespace = ns
					}
				}
			}
			for _, rr := range f.registeredResources {
				rr.Namespace = ns
				for _, value := range rr.GetValues() {
					value.Resource.Namespace = ns
					for _, aav := range value.GetActionAttributeValues() {
						aav.Action.Namespace = ns
					}
				}
			}
			action := &policy.Action{Name: "read"}
			if scopedAction {
				action.Namespace = ns
			}
			for _, entityIsRR := range []bool{false, true} {
				entity := entityChainIdentifier()
				resources := []*authzV2.Resource{{Resource: &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: fixtureRRAlpha}}}
				if entityIsRR {
					entity = &authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{RegisteredResourceValueFqn: fixtureRRAlpha}}
					resources = []*authzV2.Resource{{Resource: &authzV2.Resource_AttributeValues_{AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{fixtureSecret}}}}}
				}
				ctx := audit.ContextWithActorID(t.Context(), "test-actor")
				full := regressionDecision(ctx, t, f, f.registeredResourcesClient(), true, strict, entity, action, resources)
				targeted := regressionDecision(ctx, t, f, f.registeredResourcesClient(), false, strict, entity, action, resources)
				assert.True(t, targeted.AllPermitted, "strict=%v scopedAction=%v entityIsRR=%v", strict, scopedAction, entityIsRR)
				assert.Equal(t, full, targeted)
			}
		}
	}
}

func TestJITPDP_TargetedLegacyAliasIndependentOfRequestOrder(t *testing.T) {
	for _, tied := range []bool{false, true} {
		f := newTargetedPolicyFixture()
		older := registeredResourceValue("older-value", "b", "system", "shared", actionAttributeValue(fixtureSecret))
		newer := registeredResourceValue("newer-value", "a", "system", "shared", actionAttributeValue(fixtureConfidential))
		older.Resource.Namespace = &policy.Namespace{Name: "older.example", Fqn: "https://older.example"}
		newer.Resource.Namespace = &policy.Namespace{Name: "newer.example", Fqn: "https://newer.example"}
		older.Resource.Metadata = &common.Metadata{CreatedAt: timestamppb.New(time.Unix(10, 0))}
		newer.Resource.Metadata = &common.Metadata{CreatedAt: timestamppb.New(time.Unix(20, 0))}
		if tied {
			newer.Resource.Metadata = older.GetResource().GetMetadata()
		}
		f.registeredResources = nil
		for _, v := range []*policy.RegisteredResourceValue{newer, older} {
			parent := v.GetResource()
			f.registeredResources = append(f.registeredResources, &policy.RegisteredResource{
				Id: parent.GetId(), Name: parent.GetName(), Namespace: parent.GetNamespace(), Metadata: parent.GetMetadata(), Values: []*policy.RegisteredResourceValue{v},
			})
		}
		const legacy = "https://reg_res/system/value/shared"
		const qualified = "https://newer.example/reg_res/system/value/shared"
		fake := func() *fakeRegisteredResourcesClient {
			// The SQL regression test separately checks which value a legacy lookup returns.
			return &fakeRegisteredResourcesClient{valuesByFQN: map[string]*policy.RegisteredResourceValue{legacy: older, qualified: newer}}
		}
		entity := &authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{RegisteredResourceValueFqn: qualified}}
		for _, fqns := range [][]string{{legacy, qualified}, {qualified, legacy}} {
			resources := make([]*authzV2.Resource, 0, len(fqns))
			for _, fqn := range fqns {
				resources = append(resources, &authzV2.Resource{Resource: &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: fqn}})
			}
			ctx := audit.ContextWithActorID(t.Context(), "test-actor")
			full := regressionDecision(ctx, t, f, fake(), true, false, entity, &policy.Action{Name: "read"}, resources)
			targeted := regressionDecision(ctx, t, f, fake(), false, false, entity, &policy.Action{Name: "read"}, resources)
			assert.False(t, targeted.AllPermitted, "legacy target must require the older resource's secret entitlement")
			assert.Equal(t, full, targeted, "tied=%v order=%v", tied, fqns)
			for i, fqn := range fqns {
				assert.Equal(t, fqn == qualified, targeted.Results[i].Entitled)
			}
		}
		// Indexing a cache must not reorder its shared slice.
		assert.Equal(t, "a", f.registeredResources[0].GetId())
	}
}

func TestJITPDP_TargetedMalformedResourceDoesNotAbortMixedDecision(t *testing.T) {
	f := newTargetedPolicyFixture()
	const malformed = "https://example.com/not-a-registered-resource"
	rr := f.registeredResourcesClient()
	rr.errByFQN = map[string]error{malformed: connect.NewError(connect.CodeInternal, errors.New("invalid fqn"))}
	resources := []*authzV2.Resource{
		{Resource: &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: malformed}},
		{Resource: &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: fixtureRRAlpha}},
	}
	ctx := audit.ContextWithActorID(t.Context(), "test-actor")
	full := regressionDecision(ctx, t, f, f.registeredResourcesClient(), true, false, entityChainIdentifier(), &policy.Action{Name: "read"}, resources)
	targeted := regressionDecision(ctx, t, f, rr, false, false, entityChainIdentifier(), &policy.Action{Name: "read"}, resources)
	assert.Equal(t, full, targeted)
	assert.False(t, targeted.Results[0].Entitled)
	assert.True(t, targeted.Results[1].Entitled)
	assert.Equal(t, []string{fixtureRRAlpha}, rr.requested)
}
