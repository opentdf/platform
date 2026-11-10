package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
)

func (h Handler) CreateProviderConfig(
	ctx context.Context,
	name, manager string,
	config []byte,
	metadata *common.MetadataMutable) (*policy.KeyProviderConfig, error) {
	req := keymanagement.CreateProviderConfigRequest{
		Name:       name,
		Manager:    manager,
		ConfigJson: config,
		Metadata:   metadata,
	}

	resp, err := h.sdk.KeyManagement.CreateProviderConfig(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetProviderConfig(), nil
}

func (h Handler) GetProviderConfig(ctx context.Context, id, name string) (*policy.KeyProviderConfig, error) {
	req := keymanagement.GetProviderConfigRequest{}
	if id != "" {
		req.Identifier = &keymanagement.GetProviderConfigRequest_Id{
			Id: id,
		}
	} else if name != "" {
		req.Identifier = &keymanagement.GetProviderConfigRequest_Name{
			Name: name,
		}
	}

	resp, err := h.sdk.KeyManagement.GetProviderConfig(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetProviderConfig(), nil
}

func (h Handler) UpdateProviderConfig(
	ctx context.Context,
	id, name, manager string,
	config []byte,
	metadata *common.MetadataMutable,
	behavior common.MetadataUpdateEnum) (*policy.KeyProviderConfig, error) {
	req := keymanagement.UpdateProviderConfigRequest{
		Id:                     id,
		Name:                   name,
		Manager:                manager,
		ConfigJson:             config,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	}

	resp, err := h.sdk.KeyManagement.UpdateProviderConfig(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetProviderConfig(), nil
}

func (h Handler) ListProviderConfigs(ctx context.Context, limit, offset int32) (*keymanagement.ListProviderConfigsResponse, error) {
	req := keymanagement.ListProviderConfigsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	}

	return h.sdk.KeyManagement.ListProviderConfigs(ctx, &req)
}

func (h *Handler) DeleteProviderConfig(ctx context.Context, id string) error {
	_, err := h.sdk.KeyManagement.DeleteProviderConfig(ctx, &keymanagement.DeleteProviderConfigRequest{
		Id: id,
	})
	if err != nil {
		return err
	}
	return nil
}
