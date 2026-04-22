package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
)

// GetBaseKey retrieves a base key from the KAS registry.
// This is a stub function and needs to be implemented.
func (h Handler) GetBaseKey(ctx context.Context) (*policy.SimpleKasKey, error) {
	resp, err := h.sdk.KeyAccessServerRegistry.GetBaseKey(ctx, &kasregistry.GetBaseKeyRequest{})
	if err != nil {
		return nil, err
	}

	return resp.GetBaseKey(), nil
}

func (h Handler) SetBaseKey(ctx context.Context, id string, key *kasregistry.KasKeyIdentifier) (*kasregistry.SetBaseKeyResponse, error) {
	req := kasregistry.SetBaseKeyRequest{}

	if id != "" && key == nil {
		req.ActiveKey = &kasregistry.SetBaseKeyRequest_Id{
			Id: id,
		}
	} else if key != nil {
		req.ActiveKey = &kasregistry.SetBaseKeyRequest_Key{
			Key: key,
		}
	}

	return h.sdk.KeyAccessServerRegistry.SetBaseKey(ctx, &req)
}
