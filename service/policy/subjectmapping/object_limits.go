package subjectmapping

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	policyconfig "github.com/opentdf/platform/service/policy/config"
)

type objectLimitCounter interface {
	GetCountSubjectMappings(context.Context, string) (int64, error)
	GetCountSubjectConditionSets(context.Context, string, string) (int64, error)
	GetCountActionsWithNewAdditions(context.Context, string, string, []string) (int64, int64, error)
}

func (s SubjectMappingService) enforceCreateSubjectMappingLimits(ctx context.Context, client objectLimitCounter, req *sm.CreateSubjectMappingRequest) error {
	limits := s.config.MaxObjectCounts
	if limits.SubjectMappingsPerAttributeValue > 0 {
		count, err := client.GetCountSubjectMappings(ctx, req.GetAttributeValueId())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectMappingsPerAttributeValue, limits.SubjectMappingsPerAttributeValue, count, 1); err != nil {
			return err
		}
	}
	if limits.SubjectConditionSetsPerNamespace > 0 && req.GetNewSubjectConditionSet() != nil && req.GetExistingSubjectConditionSetId() == "" {
		count, err := client.GetCountSubjectConditionSets(ctx, req.GetNamespaceId(), req.GetNamespaceFqn())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectConditionSetsPerNamespace, limits.SubjectConditionSetsPerNamespace, count, 1); err != nil {
			return err
		}
	}
	return enforceActionNamesLimit(ctx, client, limits.ActionsPerNamespace, req.GetNamespaceId(), req.GetNamespaceFqn(), actionNames(req.GetActions()))
}

func enforceActionNamesLimit(ctx context.Context, client objectLimitCounter, limit int64, namespaceID, namespaceFQN string, names []string) error {
	if limit == 0 || len(names) == 0 {
		return nil
	}
	current, additions, err := client.GetCountActionsWithNewAdditions(ctx, namespaceID, namespaceFQN, names)
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeActionsPerNamespace, limit, current, int(additions))
}

func actionNames(actions []*policy.Action) []string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		if action.GetId() == "" && action.GetName() != "" {
			names = append(names, action.GetName())
		}
	}
	return names
}

func (s SubjectMappingService) enforceCreateSubjectConditionSetLimit(ctx context.Context, client objectLimitCounter, req *sm.CreateSubjectConditionSetRequest) error {
	limit := s.config.MaxObjectCounts.SubjectConditionSetsPerNamespace
	if limit == 0 {
		return nil
	}
	count, err := client.GetCountSubjectConditionSets(ctx, req.GetNamespaceId(), req.GetNamespaceFqn())
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectConditionSetsPerNamespace, limit, count, 1)
}
