package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
)

//
// Registered Resources
//

func (h Handler) CreateRegisteredResource(ctx context.Context, name string, values []string, metadata *common.MetadataMutable) (*policy.RegisteredResource, error) {
	resp, err := h.sdk.RegisteredResources.CreateRegisteredResource(ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name:     name,
		Values:   values,
		Metadata: metadata,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetResource(), nil
}

func (h Handler) GetRegisteredResource(ctx context.Context, id, name string) (*policy.RegisteredResource, error) {
	req := &registeredresources.GetRegisteredResourceRequest{}
	if id != "" {
		req.Identifier = &registeredresources.GetRegisteredResourceRequest_Id{
			Id: id,
		}
	} else {
		req.Identifier = &registeredresources.GetRegisteredResourceRequest_Name{
			Name: name,
		}
	}

	resp, err := h.sdk.RegisteredResources.GetRegisteredResource(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetResource(), nil
}

func (h Handler) ListRegisteredResources(ctx context.Context, limit, offset int32) (*registeredresources.ListRegisteredResourcesResponse, error) {
	return h.sdk.RegisteredResources.ListRegisteredResources(ctx, &registeredresources.ListRegisteredResourcesRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

func (h Handler) UpdateRegisteredResource(ctx context.Context, id, name string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.RegisteredResource, error) {
	_, err := h.sdk.RegisteredResources.UpdateRegisteredResource(ctx, &registeredresources.UpdateRegisteredResourceRequest{
		Id:                     id,
		Name:                   name,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetRegisteredResource(ctx, id, "")
}

func (h Handler) DeleteRegisteredResource(ctx context.Context, id string) error {
	_, err := h.sdk.RegisteredResources.DeleteRegisteredResource(ctx, &registeredresources.DeleteRegisteredResourceRequest{
		Id: id,
	})

	return err
}

//
// Registered Resource Values
//

func (h Handler) CreateRegisteredResourceValue(ctx context.Context, resourceID string, value string, actionAttributeValues []*registeredresources.ActionAttributeValue, metadata *common.MetadataMutable) (*policy.RegisteredResourceValue, error) {
	resp, err := h.sdk.RegisteredResources.CreateRegisteredResourceValue(ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId:            resourceID,
		Value:                 value,
		ActionAttributeValues: actionAttributeValues,
		Metadata:              metadata,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetValue(), nil
}

func (h Handler) GetRegisteredResourceValue(ctx context.Context, id, fqn string) (*policy.RegisteredResourceValue, error) {
	req := &registeredresources.GetRegisteredResourceValueRequest{}
	if id != "" {
		req.Identifier = &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: id,
		}
	} else {
		req.Identifier = &registeredresources.GetRegisteredResourceValueRequest_Fqn{
			Fqn: fqn,
		}
	}

	resp, err := h.sdk.RegisteredResources.GetRegisteredResourceValue(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetValue(), nil
}

func (h Handler) ListRegisteredResourceValues(ctx context.Context, resourceID string, limit, offset int32) (*registeredresources.ListRegisteredResourceValuesResponse, error) {
	return h.sdk.RegisteredResources.ListRegisteredResourceValues(ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		ResourceId: resourceID,
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

func (h Handler) UpdateRegisteredResourceValue(ctx context.Context, id, value string, actionAttributeValues []*registeredresources.ActionAttributeValue, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.RegisteredResourceValue, error) {
	_, err := h.sdk.RegisteredResources.UpdateRegisteredResourceValue(ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:                     id,
		Value:                  value,
		ActionAttributeValues:  actionAttributeValues,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetRegisteredResourceValue(ctx, id, "")
}

func (h Handler) DeleteRegisteredResourceValue(ctx context.Context, id string) error {
	_, err := h.sdk.RegisteredResources.DeleteRegisteredResourceValue(ctx, &registeredresources.DeleteRegisteredResourceValueRequest{
		Id: id,
	})

	return err
}
