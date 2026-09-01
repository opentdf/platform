package attributes

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	attributeDefinitions int64
	subjectConditionSets int64
	actionsCurrent       int64
	actionsMissing       int64
}

func (s objectLimitCounterStub) CountAttributeDefinitions(context.Context, string) (int64, error) {
	return s.attributeDefinitions, nil
}

func (objectLimitCounterStub) CountAttributeValues(context.Context, string) (int64, error) {
	return 0, nil
}

func (s objectLimitCounterStub) CountSubjectConditionSets(context.Context, string, string) (int64, error) {
	return s.subjectConditionSets, nil
}

func (s objectLimitCounterStub) CountActionsWithMissingNames(context.Context, string, string, []string) (int64, int64, error) {
	return s.actionsCurrent, s.actionsMissing, nil
}

func (objectLimitCounterStub) GetAttributeDefinitionNamespaceID(context.Context, string) (string, error) {
	return "namespace-id", nil
}

func Test_EnforceCreateAttributeLimits_AttributeDefinitionAtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &AttributesService{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{AttributeDefinitionsPerNamespace: 10}}}
	err := service.enforceCreateAttributeLimits(t.Context(), objectLimitCounterStub{attributeDefinitions: 10}, &attributes.CreateAttributeRequest{NamespaceId: "tenant-id"})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceCreateAttributeValueLimits_SubjectMappingsExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &AttributesService{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{SubjectMappingsPerAttributeValue: 10}}}
	err := service.enforceCreateAttributeValueLimits(t.Context(), objectLimitCounterStub{}, &attributes.CreateAttributeValueRequest{
		SubjectMappings: make([]*attributes.AttributeValueSubjectMappingRequest, 11),
	})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceCreateAttributeValueLimits_NestedConditionSetsExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &AttributesService{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{SubjectConditionSetsPerNamespace: 1}}}
	err := service.enforceCreateAttributeValueLimits(t.Context(), objectLimitCounterStub{subjectConditionSets: 1}, &attributes.CreateAttributeValueRequest{
		AttributeId: "attribute-id",
		SubjectMappings: []*attributes.AttributeValueSubjectMappingRequest{{
			NewSubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{},
		}},
	})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceCreateAttributeValueLimits_NestedActionsExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &AttributesService{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{ActionsPerNamespace: 5}}}
	err := service.enforceCreateAttributeValueLimits(t.Context(), objectLimitCounterStub{actionsCurrent: 4, actionsMissing: 2}, &attributes.CreateAttributeValueRequest{
		AttributeId: "attribute-id",
		SubjectMappings: []*attributes.AttributeValueSubjectMappingRequest{{
			Actions: []*policy.Action{{Name: "one"}, {Name: "two"}},
		}},
	})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
