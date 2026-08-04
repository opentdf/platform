package rttests

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/suite"
)

// Black-box regression test for the GetDecisions resource exhaustion bug
// (opentdf/platform#3821).
//
// GetDecisions returns an internal error (resource_exhausted, 4MB limit) when a request
// references FQNs from an attribute definition that has a large number of values. The
// authorization service internally calls policy's GetAttributeValuesByFqns, whose query
// returns the ENTIRE definition (all sibling values plus their subject mappings and
// condition sets) even when only a single value FQN is requested. Once the definition is
// large enough, that internal response exceeds the 4MB connect message size limit and
// surfaces to the caller as:
//
//	resource_exhausted: message size ... is larger than configured max 4194304
//
// This test drives the real GetDecisions API through the SDK against a running platform
// and treats it as a black box: it asserts only that GetDecisions succeeds. It does not
// care HOW the fix is implemented (narrowing the internal query, paginating, raising the
// limit, etc.) -- only that a request against a large attribute definition no longer
// fails. It is RED against the current code and GREEN once the bug is fixed.

// numLargeAttributeValues mirrors the ~1000-value "needtoknow" attribute opentdf/platform#3821
// medium-scale testing, at which point the internal authz->policy response first exceeded
// the 4MB connect message size limit.
const numLargeAttributeValues = 1000

func Test_GetDecisions_ResourceExhaustion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping roundtrip tests, they require the server to be up and running")
	}
	suite.Run(t, new(GetDecisionsResourceExhaustionSuite))
}

type GetDecisionsResourceExhaustionSuite struct {
	suite.Suite
	TestConfig
	client *sdk.SDK
}

func (s *GetDecisionsResourceExhaustionSuite) SetupSuite() {
	s.TestConfig = newTestConfig()
	slog.Info("test config", slog.Any("config", s.TestConfig))

	opts := []sdk.Option{}
	if os.Getenv("TLS_ENABLED") == "" {
		opts = append(opts, sdk.WithInsecurePlaintextConn())
		s.PlatformEndpointWithScheme = "http://" + s.PlatformEndpoint
	} else {
		s.PlatformEndpointWithScheme = "https://" + s.PlatformEndpoint
	}
	opts = append(opts, sdk.WithClientCredentials(s.ClientID, s.ClientSecret, nil))

	client, err := sdk.New(s.PlatformEndpointWithScheme, opts...)
	s.Require().NoError(err)
	s.client = client
}

// largePaddedSubjectExternalValues returns a matching value for the test client plus
// enough padding to make each value's embedded subject-mapping condition sizable. The
// listAttributesByDefOrValueFqns query embeds this condition JSON once per value, so a
// large condition set is what drives the aggregate internal response past 4MB.
func largePaddedSubjectExternalValues(clientID string) []string {
	values := make([]string, 0, 201)
	// real value so the subject mapping actually matches this test client -> PERMIT
	values = append(values, clientID)
	for i := range 200 {
		values = append(values, fmt.Sprintf("subject-external-value-padding-%05d", i))
	}
	return values
}

func (s *GetDecisionsResourceExhaustionSuite) Test_GetDecisions_LargeAttributeDefinition_DoesNotExhaustResources() {
	ctx := context.Background()
	client := s.client

	// Unique namespace so the test is self-contained and re-runnable against a
	// persistent server.
	nsName := fmt.Sprintf("resource-exhaustion-%d.example.com", time.Now().UnixNano())
	attrName := "needtoknow"

	nsResp, err := client.Namespaces.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{
		Name: nsName,
	})
	s.Require().NoError(err)
	nsID := nsResp.GetNamespace().GetId()

	// Build a single attribute definition with a large number of values.
	valueNames := make([]string, 0, numLargeAttributeValues)
	for i := range numLargeAttributeValues {
		valueNames = append(valueNames, fmt.Sprintf("pid-%04d", i))
	}
	attrResp, err := client.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		Name:        attrName,
		NamespaceId: nsID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      valueNames,
	})
	s.Require().NoError(err)
	createdValues := attrResp.GetAttribute().GetValues()
	s.Require().Len(createdValues, numLargeAttributeValues)

	// A single, deliberately large subject condition set shared by every value's subject
	// mapping. It matches this test client so decisions can be evaluated to PERMIT, while
	// the padding inflates the per-value condition JSON embedded in the internal response.
	scsResp, err := client.SubjectMapping.CreateSubjectConditionSet(ctx, &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".clientId",
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
									SubjectExternalValues:        largePaddedSubjectExternalValues(s.ClientID),
								},
							},
						},
					},
				},
			},
		},
	})
	s.Require().NoError(err)
	scsID := scsResp.GetSubjectConditionSet().GetId()

	// Attach a subject mapping (reusing the shared condition set) to every value so the
	// internal GetAttributeValuesByFqns response carries a condition set per value.
	slog.Info("creating subject mappings for large attribute definition", slog.Int("count", numLargeAttributeValues))
	for _, v := range createdValues {
		_, err = client.SubjectMapping.CreateSubjectMapping(ctx, &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId:              v.GetId(),
			ExistingSubjectConditionSetId: scsID,
			Actions: []*policy.Action{
				{Name: actions.ActionNameRead},
			},
		})
		s.Require().NoError(err)
	}

	// GetDecisions referencing a SINGLE value FQN from the large definition. Even one FQN
	// triggers the full-definition fetch internally, so this is enough to reproduce.
	targetFQN := createdValues[0].GetFqn()
	s.Require().NotEmpty(targetFQN)

	req := &authorization.GetDecisionsRequest{
		DecisionRequests: []*authorization.DecisionRequest{
			{
				Actions: []*policy.Action{
					{Name: actions.ActionNameRead},
				},
				EntityChains: []*authorization.EntityChain{
					{
						Id: "ec1",
						Entities: []*authorization.Entity{
							{
								Id:         "e1",
								Category:   authorization.Entity_CATEGORY_SUBJECT,
								EntityType: &authorization.Entity_ClientId{ClientId: s.ClientID},
							},
						},
					},
				},
				ResourceAttributes: []*authorization.ResourceAttribute{
					{AttributeValueFqns: []string{targetFQN}},
				},
			},
		},
	}

	// Black-box assertion: GetDecisions must not fail. Prior to the fix this returns an
	// internal error caused by resource_exhausted on the internal authz->policy call.
	resp, err := client.Authorization.GetDecisions(ctx, req)
	s.Require().NoError(err, "GetDecisions should not fail with resource_exhausted for a large attribute definition")
	s.Require().NotNil(resp)
	s.Require().NotEmpty(resp.GetDecisionResponses(), "expected at least one decision response")
}
