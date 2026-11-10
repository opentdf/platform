package handlers

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
)

type KasIdentifier struct {
	ID   string
	Name string
	URI  string
}

func (h Handler) GetKasRegistryEntry(ctx context.Context, identifer KasIdentifier) (*policy.KeyAccessServer, error) {
	req := &kasregistry.GetKeyAccessServerRequest{}
	switch {
	case identifer.ID != "":
		req.Identifier = &kasregistry.GetKeyAccessServerRequest_KasId{
			KasId: identifer.ID,
		}
	case identifer.Name != "":
		req.Identifier = &kasregistry.GetKeyAccessServerRequest_Name{
			Name: identifer.Name,
		}
	case identifer.URI != "":
		req.Identifier = &kasregistry.GetKeyAccessServerRequest_Uri{
			Uri: identifer.URI,
		}
	default:
		return nil, errors.New("id, name or uri must be provided")
	}

	resp, err := h.sdk.KeyAccessServerRegistry.GetKeyAccessServer(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetKeyAccessServer(), nil
}

func (h Handler) ListKasRegistryEntries(ctx context.Context, limit, offset int32) (*kasregistry.ListKeyAccessServersResponse, error) {
	return h.sdk.KeyAccessServerRegistry.ListKeyAccessServers(ctx, &kasregistry.ListKeyAccessServersRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// Creates the KAS registry and then returns the KAS
func (h Handler) CreateKasRegistryEntry(ctx context.Context, uri string, name string, metadata *common.MetadataMutable) (*policy.KeyAccessServer, error) {
	req := &kasregistry.CreateKeyAccessServerRequest{
		Uri:      uri,
		Name:     name,
		Metadata: metadata,
	}

	resp, err := h.sdk.KeyAccessServerRegistry.CreateKeyAccessServer(ctx, req)
	if err != nil {
		return nil, err
	}

	return h.GetKasRegistryEntry(ctx, KasIdentifier{
		ID: resp.GetKeyAccessServer().GetId(),
	})
}

// Updates the KAS registry and then returns the KAS
func (h Handler) UpdateKasRegistryEntry(ctx context.Context, id, uri, name string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.KeyAccessServer, error) {
	_, err := h.sdk.KeyAccessServerRegistry.UpdateKeyAccessServer(ctx, &kasregistry.UpdateKeyAccessServerRequest{
		Id:                     id,
		Uri:                    uri,
		Name:                   name,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetKasRegistryEntry(ctx, KasIdentifier{
		ID: id,
	})
}

// Deletes the KAS registry and returns the deleted KAS
func (h Handler) DeleteKasRegistryEntry(ctx context.Context, id string) (*policy.KeyAccessServer, error) {
	req := &kasregistry.DeleteKeyAccessServerRequest{
		Id: id,
	}

	resp, err := h.sdk.KeyAccessServerRegistry.DeleteKeyAccessServer(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetKeyAccessServer(), nil
}
