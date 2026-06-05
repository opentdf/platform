package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
)

// Creates and returns the created resource mapping
func (h *Handler) CreateResourceMappingGroup(ctx context.Context, namespaceID string, name string, metadata *common.MetadataMutable) (*policy.ResourceMappingGroup, error) {
	res, err := h.sdk.ResourceMapping.CreateResourceMappingGroup(ctx, &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: namespaceID,
		Name:        name,
		Metadata:    metadata,
	})
	if err != nil {
		return nil, err
	}

	return h.GetResourceMappingGroup(ctx, res.GetResourceMappingGroup().GetId())
}

func (h *Handler) GetResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	res, err := h.sdk.ResourceMapping.GetResourceMappingGroup(ctx, &resourcemapping.GetResourceMappingGroupRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return res.GetResourceMappingGroup(), nil
}

func (h *Handler) ListResourceMappingGroups(ctx context.Context, limit, offset int32) (*resourcemapping.ListResourceMappingGroupsResponse, error) {
	return h.sdk.ResourceMapping.ListResourceMappingGroups(ctx, &resourcemapping.ListResourceMappingGroupsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// TODO: verify updation behavior
// Updates and returns the updated resource mapping
func (h *Handler) UpdateResourceMappingGroup(ctx context.Context, id string, namespaceID string, name string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.ResourceMappingGroup, error) {
	_, err := h.sdk.ResourceMapping.UpdateResourceMappingGroup(ctx, &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:                     id,
		NamespaceId:            namespaceID,
		Name:                   name,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetResourceMappingGroup(ctx, id)
}

func (h *Handler) DeleteResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	resp, err := h.sdk.ResourceMapping.DeleteResourceMappingGroup(ctx, &resourcemapping.DeleteResourceMappingGroupRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetResourceMappingGroup(), nil
}
