package access

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	policyobligations "github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeRegisteredResourcesClient serves GetRegisteredResourceValue from a map and rejects full
// listing, so targeted decisions fail loudly if they fall back to loading everything.
type fakeRegisteredResourcesClient struct {
	sdkconnect.RegisteredResourcesServiceClient
	valuesByFQN map[string]*policy.RegisteredResourceValue
	errByFQN    map[string]error
	requested   []string
}

func (f *fakeRegisteredResourcesClient) GetRegisteredResourceValue(_ context.Context, req *registeredresources.GetRegisteredResourceValueRequest) (*registeredresources.GetRegisteredResourceValueResponse, error) {
	fqn := req.GetFqn()
	f.requested = append(f.requested, fqn)
	if err, ok := f.errByFQN[fqn]; ok {
		return nil, err
	}
	value, ok := f.valuesByFQN[fqn]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
	}
	return &registeredresources.GetRegisteredResourceValueResponse{Value: value}, nil
}

func (*fakeRegisteredResourcesClient) ListRegisteredResources(context.Context, *registeredresources.ListRegisteredResourcesRequest) (*registeredresources.ListRegisteredResourcesResponse, error) {
	return nil, errors.New("full registered resource listing is not allowed in targeted decisions")
}

// fakeObligationsClient filters and pages triggers like ListObligationTriggers and rejects full
// obligation listing.
type fakeObligationsClient struct {
	sdkconnect.ObligationsServiceClient
	triggers []*policy.ObligationTrigger
	pageSize int
	requests []*policyobligations.ListObligationTriggersRequest
}

func (f *fakeObligationsClient) ListObligationTriggers(_ context.Context, req *policyobligations.ListObligationTriggersRequest) (*policyobligations.ListObligationTriggersResponse, error) {
	f.requests = append(f.requests, req)
	var matched []*policy.ObligationTrigger
	for _, trigger := range f.triggers {
		if slices.Contains(req.GetAttributeValueFqns(), trigger.GetAttributeValue().GetFqn()) {
			matched = append(matched, trigger)
		}
	}
	pageSize := f.pageSize
	if pageSize == 0 {
		pageSize = len(matched) + 1
	}
	offset := int(req.GetPagination().GetOffset())
	end := min(offset+pageSize, len(matched))
	var next int32
	if end < len(matched) {
		next = int32(end)
	}
	return &policyobligations.ListObligationTriggersResponse{
		Triggers:   matched[offset:end],
		Pagination: &policy.PageResponse{CurrentOffset: int32(offset), NextOffset: next, Total: int32(len(matched))},
	}, nil
}

func (*fakeObligationsClient) ListObligations(context.Context, *policyobligations.ListObligationsRequest) (*policyobligations.ListObligationsResponse, error) {
	return nil, errors.New("full obligation listing is not allowed in targeted decisions")
}

func registeredResourceValue(id, resourceID, resourceName, value string, aavs ...*policy.RegisteredResourceValue_ActionAttributeValue) *policy.RegisteredResourceValue {
	return &policy.RegisteredResourceValue{
		Id:                    id,
		Value:                 value,
		Resource:              &policy.RegisteredResource{Id: resourceID, Name: resourceName, Namespace: &policy.Namespace{Name: "example.com", Fqn: "https://example.com"}},
		ActionAttributeValues: aavs,
	}
}

func actionAttributeValue(action, valueFQN string) *policy.RegisteredResourceValue_ActionAttributeValue {
	return &policy.RegisteredResourceValue_ActionAttributeValue{
		Action:         &policy.Action{Name: action},
		AttributeValue: &policy.Value{Fqn: valueFQN},
	}
}

// obligationTrigger triggers the obligation value on read of the attribute value, optionally scoped
// to PEP client IDs.
func obligationTrigger(obligationValueFQN, valueFQN string, pepClientIDs ...string) *policy.ObligationTrigger {
	trigger := &policy.ObligationTrigger{
		ObligationValue: &policy.ObligationValue{Fqn: obligationValueFQN},
		Action:          &policy.Action{Name: "read"},
		AttributeValue:  &policy.Value{Fqn: valueFQN},
	}
	for _, clientID := range pepClientIDs {
		trigger.Context = append(trigger.Context, &policy.RequestContext{Pep: &policy.PolicyEnforcementPoint{ClientId: clientID}})
	}
	return trigger
}

func TestFetchRegisteredResources_GroupsAndSkipsUnknown(t *testing.T) {
	alpha := registeredResourceValue("alpha-id", "system-id", "system", "alpha")
	beta := registeredResourceValue("beta-id", "system-id", "system", "beta")
	gamma := registeredResourceValue("gamma-id", "other-id", "other", "gamma")
	fake := &fakeRegisteredResourcesClient{
		valuesByFQN: map[string]*policy.RegisteredResourceValue{
			"https://example.com/reg_res/system/value/alpha": alpha,
			"https://reg_res/system/value/alpha":             alpha,
			"https://example.com/reg_res/system/value/beta":  beta,
			"https://example.com/reg_res/other/value/gamma":  gamma,
		},
		errByFQN: map[string]error{
			"https://example.com/reg_res/bad/value/x": connect.NewError(connect.CodeInvalidArgument, errors.New("bad fqn")),
		},
	}

	resources, err := fetchRegisteredResources(t.Context(), &otdfSDK.SDK{RegisteredResources: fake}, []string{
		"https://example.com/reg_res/system/value/ALPHA",
		"https://example.com/reg_res/system/value/alpha",
		"https://reg_res/system/value/alpha",
		"https://example.com/reg_res/system/value/beta",
		"https://example.com/reg_res/other/value/gamma",
		"https://example.com/reg_res/system/value/missing",
		"https://example.com/reg_res/bad/value/x",
		"",
	})
	require.NoError(t, err)

	// Requests are lower-cased and deduped; unknown and malformed FQNs are skipped.
	assert.Equal(t, []string{
		"https://example.com/reg_res/system/value/alpha",
		"https://reg_res/system/value/alpha",
		"https://example.com/reg_res/system/value/beta",
		"https://example.com/reg_res/other/value/gamma",
		"https://example.com/reg_res/system/value/missing",
		"https://example.com/reg_res/bad/value/x",
	}, fake.requested)

	// Values are grouped under their parent registered resources, each value once.
	require.Len(t, resources, 2)
	assert.Equal(t, "system", resources[0].GetName())
	assert.Equal(t, []*policy.RegisteredResourceValue{alpha, beta}, resources[0].GetValues())
	assert.Equal(t, "other", resources[1].GetName())
	assert.Equal(t, []*policy.RegisteredResourceValue{gamma}, resources[1].GetValues())

	indexed, err := buildRegisteredResourceValuesByFQN(resources, false)
	require.NoError(t, err)
	assert.Same(t, alpha, indexed["https://example.com/reg_res/system/value/alpha"])
	assert.Same(t, alpha, indexed["https://reg_res/system/value/alpha"])
}

func TestFetchRegisteredResources_PropagatesOtherErrors(t *testing.T) {
	fake := &fakeRegisteredResourcesClient{errByFQN: map[string]error{
		"https://example.com/reg_res/system/value/alpha": connect.NewError(connect.CodeUnavailable, errors.New("db down")),
	}}
	_, err := fetchRegisteredResources(t.Context(), &otdfSDK.SDK{RegisteredResources: fake}, []string{"https://example.com/reg_res/system/value/alpha"})
	require.ErrorIs(t, err, ErrFailedToFetchRegisteredResources)
}

func TestFetchObligationsForValues_FiltersBatchesAndPaginates(t *testing.T) {
	valueFQNs := make([]string, 0, maxTriggerValueFQNsPerRequest+10)
	triggers := make([]*policy.ObligationTrigger, 0)
	for i := range maxTriggerValueFQNsPerRequest + 10 {
		valueFQN := fmt.Sprintf("https://example.com/attr/a/value/v%d", i)
		valueFQNs = append(valueFQNs, strings.ToUpper(valueFQN))
		if i%50 == 0 {
			triggers = append(triggers, obligationTrigger(fmt.Sprintf("https://example.com/obl/o/value/%d", i), valueFQN))
		}
	}
	triggers = append(triggers, obligationTrigger("https://example.com/obl/o/value/unrelated", "https://example.com/attr/a/value/other"))
	fake := &fakeObligationsClient{triggers: triggers, pageSize: 2}

	got, err := fetchObligationsForValues(t.Context(), &otdfSDK.SDK{Obligations: fake}, valueFQNs)
	require.NoError(t, err)

	// Every trigger on a requested value is returned, wrapped in its own obligation value.
	gotFQNs := make([]string, 0, len(got))
	for _, obligation := range got {
		require.Len(t, obligation.GetValues(), 1)
		require.Len(t, obligation.GetValues()[0].GetTriggers(), 1)
		gotFQNs = append(gotFQNs, obligation.GetValues()[0].GetFqn())
	}
	assert.ElementsMatch(t, []string{
		"https://example.com/obl/o/value/0", "https://example.com/obl/o/value/50", "https://example.com/obl/o/value/100",
		"https://example.com/obl/o/value/150", "https://example.com/obl/o/value/200", "https://example.com/obl/o/value/250",
	}, gotFQNs)

	// Value FQNs are lower-cased and split at the request limit; each batch is paged.
	batchSizes := make(map[int]struct{})
	for _, req := range fake.requests {
		require.LessOrEqual(t, len(req.GetAttributeValueFqns()), maxTriggerValueFQNsPerRequest)
		for _, fqn := range req.GetAttributeValueFqns() {
			require.Equal(t, strings.ToLower(fqn), fqn)
		}
		batchSizes[len(req.GetAttributeValueFqns())] = struct{}{}
	}
	assert.Equal(t, map[int]struct{}{maxTriggerValueFQNsPerRequest: {}, 10: {}}, batchSizes)
	assert.Greater(t, len(fake.requests), 2)
}

func TestFetchObligationsForValues_NoValues(t *testing.T) {
	fake := &fakeObligationsClient{}
	got, err := fetchObligationsForValues(t.Context(), &otdfSDK.SDK{Obligations: fake}, nil)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Empty(t, fake.requests)
}

// targetedPolicyFixture is a small policy served both as fully loaded lists (as a ready cache
// would) and through the targeted lookups, so decisions from both paths can be compared.
type targetedPolicyFixture struct {
	definitions         map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition
	definitionByValue   map[string]string
	subjectMappings     map[string][]*policy.SubjectMapping
	registeredResources []*policy.RegisteredResource
	triggers            []*policy.ObligationTrigger
}

const (
	fixtureClassification = "https://example.com/attr/classification"
	fixtureProject        = "https://example.com/attr/project"
	fixtureSecret         = fixtureClassification + "/value/secret"
	fixtureConfidential   = fixtureClassification + "/value/confidential"
	fixtureAlpha          = fixtureProject + "/value/alpha"
	fixtureBeta           = fixtureProject + "/value/beta"
	fixtureWatermark      = "https://example.com/obl/drm/value/watermark"
	fixtureAuditLog       = "https://example.com/obl/drm/value/audit"
	fixtureRRAlpha        = "https://example.com/reg_res/system/value/alpha-sys"
	fixtureRRBeta         = "https://example.com/reg_res/system/value/beta-sys"
	fixtureRRMissing      = "https://example.com/reg_res/system/value/missing"
)

func newTargetedPolicyFixture() *targetedPolicyFixture {
	readByClient := func(valueFQN string) *policy.SubjectMapping {
		return &policy.SubjectMapping{
			Id:                  "sm-" + valueFQN,
			AttributeValue:      &policy.Value{Fqn: valueFQN},
			SubjectConditionSet: clientIDInConditionSet("abc"),
			Actions:             []*policy.Action{{Name: "read"}},
		}
	}
	alphaSys := registeredResourceValue("alpha-sys-id", "system-id", "system", "alpha-sys", actionAttributeValue("read", fixtureSecret))
	betaSys := registeredResourceValue("beta-sys-id", "system-id", "system", "beta-sys", actionAttributeValue("read", fixtureBeta))
	return &targetedPolicyFixture{
		definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
			fixtureClassification: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
			fixtureProject:        {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF},
		},
		definitionByValue: map[string]string{
			fixtureSecret: fixtureClassification, fixtureConfidential: fixtureClassification,
			fixtureAlpha: fixtureProject, fixtureBeta: fixtureProject,
		},
		subjectMappings: map[string][]*policy.SubjectMapping{
			fixtureSecret: {readByClient(fixtureSecret)}, fixtureConfidential: {readByClient(fixtureConfidential)},
			fixtureAlpha: {readByClient(fixtureAlpha)},
		},
		registeredResources: []*policy.RegisteredResource{{
			Id: "system-id", Name: "system", Namespace: &policy.Namespace{Name: "example.com", Fqn: "https://example.com"},
			Values: []*policy.RegisteredResourceValue{alphaSys, betaSys},
		}},
		triggers: []*policy.ObligationTrigger{
			obligationTrigger(fixtureWatermark, fixtureSecret),
			obligationTrigger(fixtureAuditLog, fixtureAlpha, "pep-1"),
			obligationTrigger(fixtureAuditLog, fixtureBeta),
		},
	}
}

func (f *targetedPolicyFixture) attributesClient() *fakeAttributesClient {
	return &fakeAttributesClient{respFunc: func(req *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
		rsp := &attrs.GetEntitleableAttributesByFqnsResponse{
			Definitions:              map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{},
			FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{},
		}
		for _, fqn := range req.GetFqns() {
			definitionFQN, ok := f.definitionByValue[fqn]
			if !ok {
				continue
			}
			rsp.Definitions[definitionFQN] = f.definitions[definitionFQN]
			rsp.FqnEntitleableAttributes[fqn] = &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
				DefinitionFqn: definitionFQN,
				Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
					Fqn: fqn, ValueId: fqn, Active: wrapperspb.Bool(true), SubjectMappings: f.subjectMappings[fqn],
				},
			}
		}
		return rsp, nil
	}}
}

func (f *targetedPolicyFixture) registeredResourcesClient() *fakeRegisteredResourcesClient {
	valuesByFQN, err := buildRegisteredResourceValuesByFQN(f.registeredResources, false)
	if err != nil {
		panic(err)
	}
	return &fakeRegisteredResourcesClient{valuesByFQN: valuesByFQN}
}

// obligations groups the fixture's triggers the way ListObligations returns them.
func (f *targetedPolicyFixture) obligations() []*policy.Obligation {
	valuesByFQN := make(map[string]*policy.ObligationValue)
	definition := &policy.Obligation{Name: "drm"}
	for _, trigger := range f.triggers {
		fqn := trigger.GetObligationValue().GetFqn()
		value, ok := valuesByFQN[fqn]
		if !ok {
			value = &policy.ObligationValue{Fqn: fqn}
			valuesByFQN[fqn] = value
			definition.Values = append(definition.Values, value)
		}
		value.Triggers = append(value.Triggers, trigger)
	}
	return []*policy.Obligation{definition}
}

// fullPolicyStore is a ready cache holding the fixture's registered resources and obligations.
type fullPolicyStore struct {
	EntitlementPolicyStore
	fixture *targetedPolicyFixture
}

func (fullPolicyStore) IsEnabled() bool              { return true }
func (fullPolicyStore) IsReady(context.Context) bool { return true }
func (s fullPolicyStore) ListAllRegisteredResources(context.Context) ([]*policy.RegisteredResource, error) {
	return s.fixture.registeredResources, nil
}

func (s fullPolicyStore) ListAllObligations(context.Context) ([]*policy.Obligation, error) {
	return s.fixture.obligations(), nil
}

func sortedDecision(d *Decision) *Decision {
	for i := range d.Results {
		slices.Sort(d.Results[i].RequiredObligationValueFQNs)
	}
	return d
}

func TestJITPDP_TargetedDecisionsMatchFullPolicy(t *testing.T) {
	fixture := newTargetedPolicyFixture()
	newSDK := func() (*otdfSDK.SDK, *fakeRegisteredResourcesClient, *fakeObligationsClient) {
		rr := fixture.registeredResourcesClient()
		obl := &fakeObligationsClient{triggers: fixture.triggers}
		ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
			EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
		}}
		return &otdfSDK.SDK{
			Attributes: fixture.attributesClient(), EntityResolutionV2: ers,
			RegisteredResources: rr, Obligations: obl,
		}, rr, obl
	}
	attributeResources := func(fqns ...string) []*authzV2.Resource {
		resources := make([]*authzV2.Resource, 0, len(fqns))
		for _, fqn := range fqns {
			resources = append(resources, &authzV2.Resource{Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{fqn}},
			}})
		}
		return resources
	}
	registeredResource := func(fqn string) *authzV2.Resource {
		return &authzV2.Resource{Resource: &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: fqn}}
	}
	registeredResourceEntity := func(fqn string) *authzV2.EntityIdentifier {
		return &authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{RegisteredResourceValueFqn: fqn}}
	}

	for _, tc := range []struct {
		name        string
		entity      *authzV2.EntityIdentifier
		action      string
		resources   []*authzV2.Resource
		pepClientID string
		fulfillable []string
		// valueFQNs are the attribute values whose obligation triggers a targeted decision may read.
		valueFQNs  []string
		wantPermit bool
		wantErr    bool
	}{
		{name: "obligation_unfulfilled", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureSecret), valueFQNs: []string{fixtureSecret}},
		{name: "obligation_fulfilled", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureSecret), fulfillable: []string{fixtureWatermark}, valueFQNs: []string{fixtureSecret}, wantPermit: true},
		{name: "no_obligation", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureConfidential), valueFQNs: []string{fixtureConfidential}, wantPermit: true},
		{name: "unentitled_value", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureBeta), fulfillable: []string{fixtureAuditLog}, valueFQNs: []string{fixtureBeta}},
		{name: "client_scoped_obligation", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureAlpha), pepClientID: "pep-1", valueFQNs: []string{fixtureAlpha}},
		{name: "client_scoped_obligation_other_pep", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureAlpha), pepClientID: "pep-2", valueFQNs: []string{fixtureAlpha}, wantPermit: true},
		{name: "action_without_triggers", entity: entityChainIdentifier(), action: "write", resources: attributeResources(fixtureSecret), valueFQNs: []string{fixtureSecret}},
		{name: "multiple_resources", entity: entityChainIdentifier(), action: "read", resources: attributeResources(fixtureSecret, fixtureAlpha, fixtureBeta), fulfillable: []string{fixtureWatermark}, valueFQNs: []string{fixtureSecret, fixtureAlpha, fixtureBeta}},
		{name: "registered_resource", entity: entityChainIdentifier(), action: "read", resources: []*authzV2.Resource{registeredResource(fixtureRRAlpha)}, fulfillable: []string{fixtureWatermark}, valueFQNs: []string{fixtureSecret}, wantPermit: true},
		{name: "unknown_registered_resource", entity: entityChainIdentifier(), action: "read", resources: []*authzV2.Resource{registeredResource(fixtureRRMissing)}},
		{name: "mixed_resources", entity: entityChainIdentifier(), action: "read", resources: append(attributeResources(fixtureConfidential), registeredResource(fixtureRRBeta), registeredResource(fixtureRRMissing)), valueFQNs: []string{fixtureConfidential, fixtureBeta}},
		{name: "registered_resource_entity", entity: registeredResourceEntity(fixtureRRAlpha), action: "read", resources: attributeResources(fixtureSecret), fulfillable: []string{fixtureWatermark}, valueFQNs: []string{fixtureSecret}, wantPermit: true},
		{name: "registered_resource_entity_unentitled", entity: registeredResourceEntity(fixtureRRAlpha), action: "read", resources: attributeResources(fixtureSecret, fixtureConfidential), fulfillable: []string{fixtureWatermark}, valueFQNs: []string{fixtureSecret, fixtureConfidential}},
		{name: "unknown_registered_resource_entity", entity: registeredResourceEntity(fixtureRRMissing), action: "read", resources: attributeResources(fixtureSecret), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := audit.ContextWithActorID(t.Context(), "test-actor")
			var requestContext *policy.RequestContext
			if tc.pepClientID != "" {
				requestContext = &policy.RequestContext{Pep: &policy.PolicyEnforcementPoint{ClientId: tc.pepClientID}}
			}
			action := &policy.Action{Name: tc.action}

			fullSDK, _, _ := newSDK()
			full, err := NewJustInTimePDP(ctx, logger.CreateTestLogger(), fullSDK, fullPolicyStore{fixture: fixture}, false, false, false)
			require.NoError(t, err)
			require.False(t, full.targeted)
			want, wantErr := full.GetDecision(ctx, tc.entity, action, tc.resources, requestContext, tc.fulfillable)

			targetedSDK, rr, obl := newSDK()
			targeted, err := NewJustInTimePDP(ctx, logger.CreateTestLogger(), targetedSDK, &decisionPolicyStore{}, false, false, false)
			require.NoError(t, err)
			require.True(t, targeted.targeted)
			got, gotErr := targeted.GetDecision(ctx, tc.entity, action, tc.resources, requestContext, tc.fulfillable)

			if tc.wantErr {
				require.Error(t, wantErr)
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, wantErr)
			require.NoError(t, gotErr)
			assert.Equal(t, tc.wantPermit, got.AllPermitted)
			assert.Equal(t, sortedDecision(want), sortedDecision(got))

			// Targeted reads stay within the request: only its registered resources, and only
			// triggers on the attribute values being decided.
			wantRR := registeredResourceFQNsOf(tc.resources)
			if fqn := tc.entity.GetRegisteredResourceValueFqn(); fqn != "" {
				wantRR = append(wantRR, fqn)
			}
			assert.ElementsMatch(t, wantRR, rr.requested)
			var requestedValues []string
			for _, req := range obl.requests {
				requestedValues = append(requestedValues, req.GetAttributeValueFqns()...)
			}
			assert.ElementsMatch(t, tc.valueFQNs, requestedValues)
		})
	}
}
