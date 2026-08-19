package resourcemapping

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
)

type objectLimitCounter interface {
	CountResourceMappingGroups(context.Context, *resourcemapping.CreateResourceMappingGroupRequest) (int64, error)
	CountResourceMappings(context.Context, *resourcemapping.CreateResourceMappingRequest) (int64, error)
}

func (s ResourceMappingService) enforceCreateResourceMappingGroupLimit(ctx context.Context, client objectLimitCounter, req *resourcemapping.CreateResourceMappingGroupRequest) error {
	limit := s.config.ObjectLimits.ResourceMappingGroups
	if limit == 0 {
		return nil
	}
	count, err := client.CountResourceMappingGroups(ctx, req)
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeResourceMappingGroups, limit, count, 1)
}

func (s ResourceMappingService) enforceCreateResourceMappingLimit(ctx context.Context, client objectLimitCounter, req *resourcemapping.CreateResourceMappingRequest) error {
	limit := s.config.ObjectLimits.ResourceMappings
	if limit == 0 {
		return nil
	}
	count, err := client.CountResourceMappings(ctx, req)
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeResourceMappings, limit, count, 1)
}
