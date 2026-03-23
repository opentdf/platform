package handlers

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
)

func (h Handler) GetNamespace(ctx context.Context, identifier string) (*policy.Namespace, error) {
	req := &namespaces.GetNamespaceRequest{
		Identifier: &namespaces.GetNamespaceRequest_NamespaceId{
			NamespaceId: identifier,
		},
	}
	if _, err := uuid.Parse(identifier); err != nil {
		req.Identifier = &namespaces.GetNamespaceRequest_Fqn{
			Fqn: identifier,
		}
	}

	resp, err := h.sdk.Namespaces.GetNamespace(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace [%s]: %w", identifier, err)
	}

	return resp.GetNamespace(), nil
}

func (h Handler) ListNamespaces(ctx context.Context, state common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error) {
	return h.sdk.Namespaces.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{
		State: state,
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// Creates and returns the created n
func (h Handler) CreateNamespace(ctx context.Context, name string, metadata *common.MetadataMutable) (*policy.Namespace, error) {
	resp, err := h.sdk.Namespaces.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{
		Name:     name,
		Metadata: metadata,
	})
	if err != nil {
		return nil, err
	}

	return h.GetNamespace(ctx, resp.GetNamespace().GetId())
}

// Updates and returns the updated namespace
func (h Handler) UpdateNamespace(ctx context.Context, id string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.Namespace, error) {
	_, err := h.sdk.Namespaces.UpdateNamespace(ctx, &namespaces.UpdateNamespaceRequest{
		Id:                     id,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}
	return h.GetNamespace(ctx, id)
}

// Deactivates and returns the deactivated namespace
func (h Handler) DeactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	_, err := h.sdk.Namespaces.DeactivateNamespace(ctx, &namespaces.DeactivateNamespaceRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return h.GetNamespace(ctx, id)
}

// Reactivates and returns the reactivated namespace
func (h Handler) UnsafeReactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	_, err := h.sdk.Unsafe.UnsafeReactivateNamespace(ctx, &unsafe.UnsafeReactivateNamespaceRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return h.GetNamespace(ctx, id)
}

// Deletes and returns the deleted namespace
func (h Handler) UnsafeDeleteNamespace(ctx context.Context, id string, fqn string) error {
	_, err := h.sdk.Unsafe.UnsafeDeleteNamespace(ctx, &unsafe.UnsafeDeleteNamespaceRequest{
		Id:  id,
		Fqn: fqn,
	})
	return err
}

// Unsafely updates the namespace and returns the renamed namespace
func (h Handler) UnsafeUpdateNamespace(ctx context.Context, id, name string) (*policy.Namespace, error) {
	_, err := h.sdk.Unsafe.UnsafeUpdateNamespace(ctx, &unsafe.UnsafeUpdateNamespaceRequest{
		Id:   id,
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	return h.GetNamespace(ctx, id)
}

// AssignKeyToAttributeNamespace assigns a KAS key to an attribute namespace
func (h *Handler) AssignKeyToAttributeNamespace(ctx context.Context, namespace, keyID string) (*namespaces.NamespaceKey, error) {
	namespaceKey := &namespaces.NamespaceKey{
		KeyId:       keyID,
		NamespaceId: namespace,
	}

	if _, err := uuid.Parse(namespace); err != nil {
		ns, err := h.GetNamespace(ctx, namespace)
		if err != nil {
			return nil, err
		}
		namespaceKey.NamespaceId = ns.GetId()
	}

	resp, err := h.sdk.Namespaces.AssignPublicKeyToNamespace(ctx, &namespaces.AssignPublicKeyToNamespaceRequest{
		NamespaceKey: namespaceKey,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetNamespaceKey(), nil
}

// RemoveKeyFromAttributeNamespace removes a KAS key from an attribute namespace
func (h *Handler) RemoveKeyFromAttributeNamespace(ctx context.Context, namespace, keyID string) error {
	namespaceKey := &namespaces.NamespaceKey{
		KeyId:       keyID,
		NamespaceId: namespace,
	}

	if _, err := uuid.Parse(namespace); err != nil {
		ns, err := h.GetNamespace(ctx, namespace)
		if err != nil {
			return err
		}
		namespaceKey.NamespaceId = ns.GetId()
	}

	_, err := h.sdk.Namespaces.RemovePublicKeyFromNamespace(ctx, &namespaces.RemovePublicKeyFromNamespaceRequest{
		NamespaceKey: namespaceKey,
	})
	return err
}
