//nolint:staticcheck // deprecated KAS grant functions are still supported while migrating
package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
)

func (h Handler) DeleteKasGrantFromAttribute(ctx context.Context, attrID string, kasID string) (*attributes.AttributeKeyAccessServer, error) {
	kas := &attributes.AttributeKeyAccessServer{
		AttributeId:       attrID,
		KeyAccessServerId: kasID,
	}
	resp, err := h.sdk.Attributes.RemoveKeyAccessServerFromAttribute(ctx, &attributes.RemoveKeyAccessServerFromAttributeRequest{
		AttributeKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetAttributeKeyAccessServer(), nil
}

func (h Handler) DeleteKasGrantFromValue(ctx context.Context, valID string, kasID string) (*attributes.ValueKeyAccessServer, error) {
	kas := &attributes.ValueKeyAccessServer{
		ValueId:           valID,
		KeyAccessServerId: kasID,
	}
	resp, err := h.sdk.Attributes.RemoveKeyAccessServerFromValue(ctx, &attributes.RemoveKeyAccessServerFromValueRequest{
		ValueKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetValueKeyAccessServer(), nil
}

func (h Handler) DeleteKasGrantFromNamespace(ctx context.Context, nsID string, kasID string) (*namespaces.NamespaceKeyAccessServer, error) {
	kas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       nsID,
		KeyAccessServerId: kasID,
	}
	resp, err := h.sdk.Namespaces.RemoveKeyAccessServerFromNamespace(ctx, &namespaces.RemoveKeyAccessServerFromNamespaceRequest{
		NamespaceKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetNamespaceKeyAccessServer(), nil
}

func (h Handler) ListKasGrants(ctx context.Context, kasID, kasURI string, limit, offset int32) ([]*kasregistry.KeyAccessServerGrants, *policy.PageResponse, error) {
	resp, err := h.sdk.KeyAccessServerRegistry.ListKeyAccessServerGrants(ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasId:  kasID,
		KasUri: kasURI,
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	//nolint:staticcheck // deprecated but not removed while public keys work is experimental
	return resp.GetGrants(), resp.GetPagination(), nil
}
