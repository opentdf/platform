package subjectmapping

import (
	"context"
	"testing"

	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	subjectMappings int64
}

func (s objectLimitCounterStub) CountSubjectMappings(context.Context, *sm.CreateSubjectMappingRequest) (int64, error) {
	return s.subjectMappings, nil
}

func (objectLimitCounterStub) CountSubjectConditionSets(context.Context, string, string) (int64, error) {
	return 0, nil
}

func Test_EnforceCreateSubjectMappingLimits_SubjectMappingAtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := SubjectMappingService{config: &policyconfig.Config{ObjectLimits: policyconfig.ObjectLimits{SubjectMappings: 10}}}
	err := service.enforceCreateSubjectMappingLimits(t.Context(), objectLimitCounterStub{subjectMappings: 10}, &sm.CreateSubjectMappingRequest{})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
