package handlers

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
)

type RotateKeyResult struct {
	KasKey           *policy.KasKey                `json:"kas_key"`
	RotatedResources *kasregistry.RotatedResources `json:"rotated_resources"`
}

func (h Handler) CreateKasKey(
	ctx context.Context,
	kasID string,
	keyID string,
	alg policy.Algorithm,
	mode policy.KeyMode,
	pubKeyCtx *policy.PublicKeyCtx,
	privKeyCtx *policy.PrivateKeyCtx,
	providerConfigID string,
	metadata *common.MetadataMutable,
	legacy bool,
) (*policy.KasKey, error) {
	req := kasregistry.CreateKeyRequest{
		KasId:            kasID,
		KeyId:            keyID,
		KeyAlgorithm:     alg,
		KeyMode:          mode,
		PublicKeyCtx:     pubKeyCtx,
		PrivateKeyCtx:    privKeyCtx,
		ProviderConfigId: providerConfigID,
		Metadata:         metadata,
		Legacy:           legacy,
	}

	resp, err := h.sdk.KeyAccessServerRegistry.CreateKey(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetKasKey(), nil
}

func (h Handler) GetKasKey(ctx context.Context, id string, key *kasregistry.KasKeyIdentifier) (*policy.KasKey, error) {
	req := kasregistry.GetKeyRequest{}
	switch {
	case id != "" && key == nil:
		req.Identifier = &kasregistry.GetKeyRequest_Id{
			Id: id,
		}
	case key != nil:
		req.Identifier = &kasregistry.GetKeyRequest_Key{
			Key: key,
		}
	default:
		return nil, errors.New("id or key must be provided")
	}

	resp, err := h.sdk.KeyAccessServerRegistry.GetKey(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetKasKey(), nil
}

func (h Handler) UpdateKasKey(ctx context.Context, id string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.KasKey, error) {
	req := kasregistry.UpdateKeyRequest{
		Id:                     id,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	}

	resp, err := h.sdk.KeyAccessServerRegistry.UpdateKey(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetKasKey(), nil
}

func (h Handler) ListKasKeys(
	ctx context.Context,
	limit, offset int32,
	algorithm policy.Algorithm,
	identifier KasIdentifier,
	legacy *bool) (*kasregistry.ListKeysResponse, error) {
	req := kasregistry.ListKeysRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
		KeyAlgorithm: algorithm,
	}

	switch {
	case identifier.ID != "":
		req.KasFilter = &kasregistry.ListKeysRequest_KasId{
			KasId: identifier.ID,
		}
	case identifier.Name != "":
		req.KasFilter = &kasregistry.ListKeysRequest_KasName{
			KasName: identifier.Name,
		}
	case identifier.URI != "":
		req.KasFilter = &kasregistry.ListKeysRequest_KasUri{
			KasUri: identifier.URI,
		}
	}
	req.Legacy = legacy

	return h.sdk.KeyAccessServerRegistry.ListKeys(ctx, &req)
}

func (h Handler) ListKeyMappings(
	ctx context.Context,
	limit, offset int32,
	keySystemID string,
	keyUserIdentifier *kasregistry.KasKeyIdentifier,
) (*kasregistry.ListKeyMappingsResponse, error) {
	req := kasregistry.ListKeyMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	}

	switch {
	case keySystemID != "":
		req.Identifier = &kasregistry.ListKeyMappingsRequest_Id{
			Id: keySystemID,
		}
	case keyUserIdentifier != nil:
		req.Identifier = &kasregistry.ListKeyMappingsRequest_Key{
			Key: keyUserIdentifier,
		}
	}

	resp, err := h.sdk.KeyAccessServerRegistry.ListKeyMappings(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h Handler) RotateKasKey(
	ctx context.Context,
	oldKeyID string,
	key *kasregistry.KasKeyIdentifier,
	newKey *kasregistry.RotateKeyRequest_NewKey,
) (*RotateKeyResult, error) {
	req := kasregistry.RotateKeyRequest{
		NewKey: newKey,
	}

	switch {
	case oldKeyID != "" && key == nil:
		req.ActiveKey = &kasregistry.RotateKeyRequest_Id{
			Id: oldKeyID,
		}
	case key != nil:
		req.ActiveKey = &kasregistry.RotateKeyRequest_Key{
			Key: key,
		}
	default:
		return nil, errors.New("old key id or key must be provided")
	}

	resp, err := h.sdk.KeyAccessServerRegistry.RotateKey(ctx, &req)
	if err != nil {
		return nil, err
	}

	return &RotateKeyResult{
		KasKey:           resp.GetKasKey(),
		RotatedResources: resp.GetRotatedResources(),
	}, nil
}

func (h Handler) UnsafeDeleteKasKey(ctx context.Context, id, kid, kasURI string) (*policy.KasKey, error) {
	resp, err := h.sdk.Unsafe.UnsafeDeleteKasKey(ctx, &unsafe.UnsafeDeleteKasKeyRequest{
		Id:     id,
		Kid:    kid,
		KasUri: kasURI,
	})
	return resp.GetKey(), err
}
