package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

// DynamicValueMappingOperatorEnumChoices are the operators supported by a dynamic value resolver.
// NOT_IN and UNSPECIFIED are excluded: dynamic resolution is existential over the resolved entity
// values, so a negative operator is not supported.
var DynamicValueMappingOperatorEnumChoices = []string{SubjectMappingOperatorIn, SubjectMappingOperatorInContains}

func (h Handler) GetDynamicValueMapping(ctx context.Context, id string) (*policy.DynamicValueMapping, error) {
	resp, err := h.sdk.DynamicValueMapping.GetDynamicValueMapping(ctx, &dynamicvaluemapping.GetDynamicValueMappingRequest{
		Id: id,
	})
	return resp.GetDynamicValueMapping(), err
}

func (h Handler) ListDynamicValueMappings(ctx context.Context, limit, offset int32, namespace, attrDefID string, sort SortOption) (*dynamicvaluemapping.ListDynamicValueMappingsResponse, error) {
	req := &dynamicvaluemapping.ListDynamicValueMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	}
	req.NamespaceId, req.NamespaceFqn = getNamespaceIDAndFQN(namespace)
	if attrDefID != "" {
		req.AttributeDefinitionId = attrDefID
	}
	if !sort.IsZero() {
		allowedFields := map[string]dynamicvaluemapping.SortDynamicValueMappingsType{
			"created_at": dynamicvaluemapping.SortDynamicValueMappingsType_SORT_DYNAMIC_VALUE_MAPPINGS_TYPE_CREATED_AT,
			"updated_at": dynamicvaluemapping.SortDynamicValueMappingsType_SORT_DYNAMIC_VALUE_MAPPINGS_TYPE_UPDATED_AT,
		}
		field, err := sortField("dynamic value mappings", sort, allowedFields)
		if err != nil {
			return nil, err
		}
		req.Sort = []*dynamicvaluemapping.DynamicValueMappingsSort{{Field: field, Direction: sort.Direction}}
	}
	return h.sdk.DynamicValueMapping.ListDynamicValueMappings(ctx, req)
}

// Creates and returns the created dynamic value mapping
func (h Handler) CreateDynamicValueMapping(ctx context.Context, attrDefID, attrDefFQN string, resolver *policy.DynamicValueResolver, actions []*policy.Action, existingSCSID string, newSCS *subjectmapping.SubjectConditionSetCreate, namespace string, m *common.MetadataMutable) (*policy.DynamicValueMapping, error) {
	req := &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId:         attrDefID,
		AttributeDefinitionFqn:        attrDefFQN,
		ValueResolver:                 resolver,
		Actions:                       actions,
		ExistingSubjectConditionSetId: existingSCSID,
		NewSubjectConditionSet:        newSCS,
		Metadata:                      m,
	}
	req.NamespaceId, req.NamespaceFqn = getNamespaceIDAndFQN(namespace)
	resp, err := h.sdk.DynamicValueMapping.CreateDynamicValueMapping(ctx, req)
	if err != nil {
		return nil, err
	}
	return h.GetDynamicValueMapping(ctx, resp.GetDynamicValueMapping().GetId())
}

// Updates and returns the updated dynamic value mapping
func (h Handler) UpdateDynamicValueMapping(ctx context.Context, id string, resolver *policy.DynamicValueResolver, scsID string, actions []*policy.Action, m *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.DynamicValueMapping, error) {
	_, err := h.sdk.DynamicValueMapping.UpdateDynamicValueMapping(ctx, &dynamicvaluemapping.UpdateDynamicValueMappingRequest{
		Id:                     id,
		ValueResolver:          resolver,
		SubjectConditionSetId:  scsID,
		Actions:                actions,
		Metadata:               m,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}
	return h.GetDynamicValueMapping(ctx, id)
}

func (h Handler) DeleteDynamicValueMapping(ctx context.Context, id string) (*policy.DynamicValueMapping, error) {
	resp, err := h.sdk.DynamicValueMapping.DeleteDynamicValueMapping(ctx, &dynamicvaluemapping.DeleteDynamicValueMappingRequest{
		Id: id,
	})
	return resp.GetDynamicValueMapping(), err
}
