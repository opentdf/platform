package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
)

// Creates and returns the created resource mapping
func (h *Handler) CreateResourceMapping(ctx context.Context, attributeID string, terms []string, grpID, namespaceID, namespaceFqn string, metadata *common.MetadataMutable) (*policy.ResourceMapping, error) {
	res, err := h.sdk.ResourceMapping.CreateResourceMapping(ctx, &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attributeID,
		GroupId:          grpID,
		NamespaceId:      namespaceID,
		NamespaceFqn:     namespaceFqn,
		Terms:            terms,
		Metadata:         metadata,
	})
	if err != nil {
		return nil, err
	}

	return h.GetResourceMapping(ctx, res.GetResourceMapping().GetId())
}

func (h *Handler) GetResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	res, err := h.sdk.ResourceMapping.GetResourceMapping(ctx, &resourcemapping.GetResourceMappingRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return res.GetResourceMapping(), nil
}

func (h *Handler) ListResourceMappings(ctx context.Context, namespaceID, namespaceFqn string, limit, offset int32) (*resourcemapping.ListResourceMappingsResponse, error) {
	return h.sdk.ResourceMapping.ListResourceMappings(ctx, &resourcemapping.ListResourceMappingsRequest{
		NamespaceId:  namespaceID,
		NamespaceFqn: namespaceFqn,
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// TODO: verify updation behavior
// Updates and returns the updated resource mapping
func (h *Handler) UpdateResourceMapping(ctx context.Context, id, attrValueID, grpID, namespaceID, namespaceFqn string, terms []string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.ResourceMapping, error) {
	_, err := h.sdk.ResourceMapping.UpdateResourceMapping(ctx, &resourcemapping.UpdateResourceMappingRequest{
		Id:                     id,
		AttributeValueId:       attrValueID,
		Terms:                  terms,
		GroupId:                grpID,
		NamespaceId:            namespaceID,
		NamespaceFqn:           namespaceFqn,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetResourceMapping(ctx, id)
}

func (h *Handler) DeleteResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	resp, err := h.sdk.ResourceMapping.DeleteResourceMapping(ctx, &resourcemapping.DeleteResourceMappingRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetResourceMapping(), nil
}
