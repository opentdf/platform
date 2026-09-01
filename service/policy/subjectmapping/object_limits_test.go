package subjectmapping

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	subjectMappings int64
	actionsCurrent  int64
	actionsMissing  int64
}

func (s objectLimitCounterStub) CountSubjectMappings(context.Context, string) (int64, error) {
	return s.subjectMappings, nil
}

func (objectLimitCounterStub) CountSubjectConditionSets(context.Context, string, string) (int64, error) {
	return 0, nil
}

func (s objectLimitCounterStub) CountActionsWithMissingNames(context.Context, string, string, []string) (int64, int64, error) {
	return s.actionsCurrent, s.actionsMissing, nil
}

func Test_EnforceCreateSubjectMappingLimits_SubjectMappingAtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := SubjectMappingService{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{SubjectMappingsPerAttributeValue: 10}}}
	err := service.enforceCreateSubjectMappingLimits(t.Context(), objectLimitCounterStub{subjectMappings: 10}, &sm.CreateSubjectMappingRequest{})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceCreateSubjectMappingLimits_ImplicitActionsExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	service := SubjectMappingService{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{ActionsPerNamespace: 5}}}
	err := service.enforceCreateSubjectMappingLimits(t.Context(), objectLimitCounterStub{actionsCurrent: 4, actionsMissing: 2}, &sm.CreateSubjectMappingRequest{
		Actions: []*policy.Action{{Name: "one"}, {Name: "two"}},
	})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
