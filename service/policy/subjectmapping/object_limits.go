package subjectmapping

import (
	"context"

	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
)

type objectLimitCounter interface {
	CountSubjectMappings(context.Context, *sm.CreateSubjectMappingRequest) (int64, error)
	CountSubjectConditionSets(context.Context, string, string) (int64, error)
}

func (s SubjectMappingService) enforceCreateSubjectMappingLimits(ctx context.Context, client objectLimitCounter, req *sm.CreateSubjectMappingRequest) error {
	limits := s.config.ObjectLimits
	if limits.SubjectMappings > 0 {
		count, err := client.CountSubjectMappings(ctx, req)
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectMappings, limits.SubjectMappings, count, 1); err != nil {
			return err
		}
	}
	if limits.SubjectConditionSets == 0 || req.GetNewSubjectConditionSet() == nil {
		return nil
	}
	count, err := client.CountSubjectConditionSets(ctx, req.GetNamespaceId(), req.GetNamespaceFqn())
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectConditionSets, limits.SubjectConditionSets, count, 1)
}

func (s SubjectMappingService) enforceCreateSubjectConditionSetLimit(ctx context.Context, client objectLimitCounter, req *sm.CreateSubjectConditionSetRequest) error {
	limit := s.config.ObjectLimits.SubjectConditionSets
	if limit == 0 {
		return nil
	}
	count, err := client.CountSubjectConditionSets(ctx, req.GetNamespaceId(), req.GetNamespaceFqn())
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectConditionSets, limit, count, 1)
}
