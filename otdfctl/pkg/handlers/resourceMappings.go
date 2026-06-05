package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
)

// Creates and returns the created resource mapping
func (h *Handler) CreateResourceMapping(attributeID string, terms []string, grpID string, metadata *common.MetadataMutable) (*policy.ResourceMapping, error) {
	res, err := h.sdk.ResourceMapping.CreateResourceMapping(context.Background(), &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attributeID,
		GroupId:          grpID,
		Terms:            terms,
		Metadata:         metadata,
	})
	if err != nil {
		return nil, err
	}

	return h.GetResourceMapping(res.GetResourceMapping().GetId())
}

func (h *Handler) GetResourceMapping(id string) (*policy.ResourceMapping, error) {
	res, err := h.sdk.ResourceMapping.GetResourceMapping(context.Background(), &resourcemapping.GetResourceMappingRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return res.GetResourceMapping(), nil
}

func (h *Handler) ListResourceMappings(ctx context.Context, limit, offset int32) (*resourcemapping.ListResourceMappingsResponse, error) {
	return h.sdk.ResourceMapping.ListResourceMappings(ctx, &resourcemapping.ListResourceMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// TODO: verify updation behavior
// Updates and returns the updated resource mapping
func (h *Handler) UpdateResourceMapping(id string, attrValueID string, grpID string, terms []string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.ResourceMapping, error) {
	_, err := h.sdk.ResourceMapping.UpdateResourceMapping(context.Background(), &resourcemapping.UpdateResourceMappingRequest{
		Id:                     id,
		AttributeValueId:       attrValueID,
		Terms:                  terms,
		GroupId:                grpID,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetResourceMapping(id)
}

func (h *Handler) DeleteResourceMapping(id string) (*policy.ResourceMapping, error) {
	resp, err := h.sdk.ResourceMapping.DeleteResourceMapping(context.Background(), &resourcemapping.DeleteResourceMappingRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetResourceMapping(), nil
}
