package resourcemapping

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	resourceMappingGroups int64
}

func (s objectLimitCounterStub) CountResourceMappingGroups(context.Context, *resourcemapping.CreateResourceMappingGroupRequest) (int64, error) {
	return s.resourceMappingGroups, nil
}

func (objectLimitCounterStub) CountResourceMappings(context.Context, *resourcemapping.CreateResourceMappingRequest) (int64, error) {
	return 0, nil
}

func Test_EnforceCreateResourceMappingGroupLimit_AtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := ResourceMappingService{config: &policyconfig.Config{ObjectLimits: policyconfig.ObjectLimits{ResourceMappingGroups: 10}}}
	err := service.enforceCreateResourceMappingGroupLimit(t.Context(), objectLimitCounterStub{resourceMappingGroups: 10}, &resourcemapping.CreateResourceMappingGroupRequest{})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
