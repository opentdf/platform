package handlers

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
)

func (h *Handler) ListAttributeValues(ctx context.Context, attributeID string, state common.ActiveStateEnum, limit, offset int32) (*attributes.ListAttributeValuesResponse, error) {
	return h.sdk.Attributes.ListAttributeValues(ctx, &attributes.ListAttributeValuesRequest{
		AttributeId: attributeID,
		State:       state,
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// Creates and returns the created value
func (h *Handler) CreateAttributeValue(ctx context.Context, attributeID string, value string, metadata *common.MetadataMutable) (*policy.Value, error) {
	resp, err := h.sdk.Attributes.CreateAttributeValue(ctx, &attributes.CreateAttributeValueRequest{
		AttributeId: attributeID,
		Value:       value,
		Metadata:    metadata,
	})
	if err != nil {
		return nil, err
	}

	return h.GetAttributeValue(ctx, resp.GetValue().GetId())
}

func (h *Handler) GetAttributeValue(ctx context.Context, identifier string) (*policy.Value, error) {
	req := &attributes.GetAttributeValueRequest{
		Identifier: &attributes.GetAttributeValueRequest_ValueId{
			ValueId: identifier,
		},
	}
	if _, err := uuid.Parse(identifier); err != nil {
		req.Identifier = &attributes.GetAttributeValueRequest_Fqn{
			Fqn: identifier,
		}
	}
	resp, err := h.sdk.Attributes.GetAttributeValue(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get attribute value [%s]: %w", identifier, err)
	}

	return resp.GetValue(), nil
}

// Updates and returns updated value
func (h *Handler) UpdateAttributeValue(ctx context.Context, id string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.Value, error) {
	resp, err := h.sdk.Attributes.UpdateAttributeValue(ctx, &attributes.UpdateAttributeValueRequest{
		Id:                     id,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return h.GetAttributeValue(ctx, resp.GetValue().GetId())
}

// Deactivates and returns deactivated value
func (h *Handler) DeactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	_, err := h.sdk.Attributes.DeactivateAttributeValue(ctx, &attributes.DeactivateAttributeValueRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return h.GetAttributeValue(ctx, id)
}

// Reactivates and returns reactivated attribute
func (h Handler) UnsafeReactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	_, err := h.sdk.Unsafe.UnsafeReactivateAttributeValue(ctx, &unsafe.UnsafeReactivateAttributeValueRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return h.GetAttributeValue(ctx, id)
}

// Deletes and returns error if deletion failed
func (h Handler) UnsafeDeleteAttributeValue(ctx context.Context, id, fqn string) error {
	_, err := h.sdk.Unsafe.UnsafeDeleteAttributeValue(ctx, &unsafe.UnsafeDeleteAttributeValueRequest{
		Id:  id,
		Fqn: fqn,
	})
	return err
}

// Deletes and returns error if deletion failed
func (h Handler) UnsafeUpdateAttributeValue(ctx context.Context, id, value string) error {
	req := &unsafe.UnsafeUpdateAttributeValueRequest{
		Id:    id,
		Value: value,
	}

	_, err := h.sdk.Unsafe.UnsafeUpdateAttributeValue(ctx, req)
	return err
}

// AssignKeyToAttributeValue assigns a KAS key to an attribute value
func (h *Handler) AssignKeyToAttributeValue(ctx context.Context, value, keyID string) (*attributes.ValueKey, error) {
	valueKey := &attributes.ValueKey{
		KeyId:   keyID,
		ValueId: value,
	}

	if _, err := uuid.Parse(value); err != nil {
		attrValue, err := h.GetAttributeValue(ctx, value)
		if err != nil {
			return nil, err
		}
		valueKey.ValueId = attrValue.GetId()
	}

	resp, err := h.sdk.Attributes.AssignPublicKeyToValue(ctx, &attributes.AssignPublicKeyToValueRequest{
		ValueKey: valueKey,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetValueKey(), nil
}

// RemoveKeyFromAttributeValue removes a KAS key from an attribute value
func (h *Handler) RemoveKeyFromAttributeValue(ctx context.Context, value, keyID string) error {
	valueKey := &attributes.ValueKey{
		KeyId:   keyID,
		ValueId: value,
	}

	if _, err := uuid.Parse(value); err != nil {
		attrValue, err := h.GetAttributeValue(ctx, value)
		if err != nil {
			return err
		}
		valueKey.ValueId = attrValue.GetId()
	}

	_, err := h.sdk.Attributes.RemovePublicKeyFromValue(ctx, &attributes.RemovePublicKeyFromValueRequest{
		ValueKey: valueKey,
	})
	return err
}
