package db

import (
	"context"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

// PolicyObjectCount contains the existing and requested counts for a namespace.
type PolicyObjectCount struct {
	NamespaceID string
	Count       int64
	Added       int64
}

func (c PolicyDBClient) CountAttributeDefinitions(ctx context.Context, namespaceID string) (int64, error) {
	return c.queries.countAttributeDefinitions(ctx, namespaceID)
}

func (c PolicyDBClient) CountAttributeValues(ctx context.Context, attributeDefinitionID string) (int64, error) {
	return c.queries.countAttributeValues(ctx, attributeDefinitionID)
}

func (c PolicyDBClient) CountResourceMappingGroups(ctx context.Context, req *resourcemapping.CreateResourceMappingGroupRequest) (int64, error) {
	return c.queries.countResourceMappingGroups(ctx, countResourceMappingGroupsParams{
		NamespaceID:  pgtypeUUID(req.GetNamespaceId()),
		NamespaceFqn: pgtypeText(req.GetNamespaceFqn()),
	})
}

func (c PolicyDBClient) CountResourceMappings(ctx context.Context, req *resourcemapping.CreateResourceMappingRequest) (int64, error) {
	return c.queries.countResourceMappings(ctx, countResourceMappingsParams{
		NamespaceID:  pgtypeUUID(req.GetNamespaceId()),
		NamespaceFqn: pgtypeText(req.GetNamespaceFqn()),
		GroupID:      pgtypeUUID(req.GetGroupId()),
	})
}

func (c PolicyDBClient) CountSubjectMappings(ctx context.Context, req *subjectmapping.CreateSubjectMappingRequest) (int64, error) {
	return c.queries.countSubjectMappings(ctx, countSubjectMappingsParams{
		NamespaceID:  pgtypeUUID(req.GetNamespaceId()),
		NamespaceFqn: pgtypeText(req.GetNamespaceFqn()),
	})
}

func (c PolicyDBClient) CountSubjectConditionSets(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	return c.queries.countSubjectConditionSets(ctx, countSubjectConditionSetsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
}

func (c PolicyDBClient) CountObligationDefinitions(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	return c.queries.countObligationDefinitions(ctx, countObligationDefinitionsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
}

func (c PolicyDBClient) CountObligationValues(ctx context.Context, obligationID, obligationFQN string) (int64, error) {
	namespaceFQN, obligationName := identifier.BreakOblFQN(obligationFQN)
	return c.queries.countObligationValues(ctx, countObligationValuesParams{
		ObligationID:   pgtypeUUID(obligationID),
		NamespaceFqn:   pgtypeText(namespaceFQN),
		ObligationName: pgtypeText(obligationName),
	})
}

func (c PolicyDBClient) CountObligationTriggersForAttributeDefinition(ctx context.Context, attributeDefinitionID string) (PolicyObjectCount, error) {
	count, err := c.queries.countObligationTriggersForAttributeDefinition(ctx, attributeDefinitionID)
	return PolicyObjectCount{NamespaceID: count.NamespaceID, Count: count.Count}, err
}

func (c PolicyDBClient) CountObligationTriggersForAttributeValues(ctx context.Context, values []*common.IdFqnIdentifier) ([]PolicyObjectCount, error) {
	countsByNamespace := make(map[string]PolicyObjectCount)
	for _, value := range values {
		row, err := c.queries.countObligationTriggersForAttributeValue(ctx, countObligationTriggersForAttributeValueParams{
			AttributeValueID:  pgtypeUUID(value.GetId()),
			AttributeValueFqn: pgtypeText(value.GetFqn()),
		})
		if err != nil {
			return nil, err
		}
		count := countsByNamespace[row.NamespaceID]
		count.NamespaceID = row.NamespaceID
		count.Count = row.Count
		count.Added++
		countsByNamespace[row.NamespaceID] = count
	}

	counts := make([]PolicyObjectCount, 0, len(countsByNamespace))
	for _, count := range countsByNamespace {
		counts = append(counts, count)
	}
	return counts, nil
}
