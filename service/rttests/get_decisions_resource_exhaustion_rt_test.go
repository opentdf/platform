package rttests

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/suite"
)

// Black-box regression test for the v2 authorization resource exhaustion bug
// (opentdf/platform#3821).
//
// The v2 authorization path builds a "just-in-time" PDP that loads EVERY subject
// mapping on the platform via store.ListAllSubjectMappings(ctx). That internal load
// is not scoped to the attributes referenced by the request, so once the total size
// of all subject mappings (each carrying its embedded subject condition set) exceeds
// the 4MB connect message size limit, the internal call fails and surfaces to the
// caller as:
//
//	resource_exhausted: message size ... is larger than configured max 4194304
//
// This test drives the real AuthorizationV2.GetDecision API through the SDK against a
// running platform and treats it as a black box: it asserts only that GetDecision
// succeeds. It does not care HOW the fix is implemented (scoping the load to the
// referenced attributes, paginating, streaming, raising the limit, etc.) -- only that
// a decision request no longer fails once enough subject-mapping data exists on the
// platform. It is RED against the current code and GREEN once the bug is fixed.

const (
	// numLargeSubjectMappings is the number of subject mappings that share one large
	// subject condition set. ListAllSubjectMappings embeds the full condition set once
	// per subject mapping, so a handful of mappings pointing at a sizable shared
	// condition set is enough to push the aggregate internal response well past 4MB
	// without any single create request approaching the 4MB send limit.
	numLargeSubjectMappings = 8

	// paddingValuesPerConditionSet controls how large the shared subject condition set
	// is. ~25k padded external values yields roughly ~1MB per condition set, so
	// numLargeSubjectMappings copies total ~8MB -- comfortably above the 4MB limit.
	paddingValuesPerConditionSet = 25000
)

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
// enough padding to make the condition set sizable. The v2 JIT PDP loads every subject
// mapping (with its embedded condition set) globally, so a large condition set shared
// across a handful of subject mappings is what drives the aggregate internal load past
// the 4MB limit.
func largePaddedSubjectExternalValues(clientID string) []string {
	values := make([]string, 0, paddingValuesPerConditionSet+1)
	// real value so the subject mapping actually matches this test client
	values = append(values, clientID)
	for i := range paddingValuesPerConditionSet {
		values = append(values, fmt.Sprintf("subject-external-value-padding-%08d", i))
	}
	return values
}

func (s *GetDecisionsResourceExhaustionSuite) Test_GetDecision_LargeSubjectMappingSet_DoesNotExhaustResources() {
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

	// One attribute with enough values to host each of our large subject mappings.
	valueNames := make([]string, 0, numLargeSubjectMappings)
	for i := range numLargeSubjectMappings {
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
	s.Require().Len(createdValues, numLargeSubjectMappings)

	// A single, deliberately large subject condition set shared by every subject
	// mapping. It matches this test client so a PERMIT can be evaluated, while the
	// padding inflates the condition JSON that ListAllSubjectMappings embeds per
	// subject mapping.
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

	// Attach a subject mapping (reusing the shared condition set) to each value so the
	// global ListAllSubjectMappings load carries the large condition set once per
	// mapping, multiplying the payload past the 4MB limit.
	slog.Info("creating large subject mappings", slog.Int("count", numLargeSubjectMappings))
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

	// v2 GetDecision referencing a single value FQN. The JIT PDP loads ALL subject
	// mappings globally regardless of the referenced FQN, so this is enough to
	// reproduce.
	targetFQN := createdValues[0].GetFqn()
	s.Require().NotEmpty(targetFQN)

	req := &authorizationv2.GetDecisionRequest{
		EntityIdentifier: &authorizationv2.EntityIdentifier{
			Identifier: &authorizationv2.EntityIdentifier_EntityChain{
				EntityChain: &entity.EntityChain{
					Entities: []*entity.Entity{
						{
							EphemeralId: "e1",
							Category:    entity.Entity_CATEGORY_SUBJECT,
							EntityType:  &entity.Entity_ClientId{ClientId: s.ClientID},
						},
					},
				},
			},
		},
		Action: &policy.Action{
			Name: actions.ActionNameRead,
		},
		Resource: &authorizationv2.Resource{
			EphemeralId: "resource1",
			Resource: &authorizationv2.Resource_AttributeValues_{
				AttributeValues: &authorizationv2.Resource_AttributeValues{
					Fqns: []string{targetFQN},
				},
			},
		},
	}

	// Black-box assertion: GetDecision must not fail. Prior to the fix this returns an
	// internal error caused by resource_exhausted while loading all subject mappings.
	resp, err := client.AuthorizationV2.GetDecision(ctx, req)
	s.Require().NoError(err, "GetDecision should not fail with resource_exhausted for a large subject-mapping set")
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.GetDecision(), "expected a decision in the response")
}
