// Wrapper for UnsafeServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnect"
)

type UnsafeServiceClientConnectWrapper struct {
	unsafeconnect.UnsafeServiceClient
}

func NewUnsafeServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *UnsafeServiceClientConnectWrapper {
	return &UnsafeServiceClientConnectWrapper{UnsafeServiceClient: unsafeconnect.NewUnsafeServiceClient(httpClient, baseURL, opts...)}
}

type UnsafeServiceClient interface {
	UnsafeUpdateNamespace(ctx context.Context, req *unsafe.UnsafeUpdateNamespaceRequest) (*unsafe.UnsafeUpdateNamespaceResponse, error)
	UnsafeReactivateNamespace(ctx context.Context, req *unsafe.UnsafeReactivateNamespaceRequest) (*unsafe.UnsafeReactivateNamespaceResponse, error)
	UnsafeDeleteNamespace(ctx context.Context, req *unsafe.UnsafeDeleteNamespaceRequest) (*unsafe.UnsafeDeleteNamespaceResponse, error)
	UnsafeUpdateAttribute(ctx context.Context, req *unsafe.UnsafeUpdateAttributeRequest) (*unsafe.UnsafeUpdateAttributeResponse, error)
	UnsafeReactivateAttribute(ctx context.Context, req *unsafe.UnsafeReactivateAttributeRequest) (*unsafe.UnsafeReactivateAttributeResponse, error)
	UnsafeDeleteAttribute(ctx context.Context, req *unsafe.UnsafeDeleteAttributeRequest) (*unsafe.UnsafeDeleteAttributeResponse, error)
	UnsafeUpdateAttributeValue(ctx context.Context, req *unsafe.UnsafeUpdateAttributeValueRequest) (*unsafe.UnsafeUpdateAttributeValueResponse, error)
	UnsafeReactivateAttributeValue(ctx context.Context, req *unsafe.UnsafeReactivateAttributeValueRequest) (*unsafe.UnsafeReactivateAttributeValueResponse, error)
	UnsafeDeleteAttributeValue(ctx context.Context, req *unsafe.UnsafeDeleteAttributeValueRequest) (*unsafe.UnsafeDeleteAttributeValueResponse, error)
	UnsafeDeleteKasKey(ctx context.Context, req *unsafe.UnsafeDeleteKasKeyRequest) (*unsafe.UnsafeDeleteKasKeyResponse, error)
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeUpdateNamespace(ctx context.Context, req *unsafe.UnsafeUpdateNamespaceRequest) (*unsafe.UnsafeUpdateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeUpdateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeReactivateNamespace(ctx context.Context, req *unsafe.UnsafeReactivateNamespaceRequest) (*unsafe.UnsafeReactivateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeReactivateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteNamespace(ctx context.Context, req *unsafe.UnsafeDeleteNamespaceRequest) (*unsafe.UnsafeDeleteNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeUpdateAttribute(ctx context.Context, req *unsafe.UnsafeUpdateAttributeRequest) (*unsafe.UnsafeUpdateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeUpdateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeReactivateAttribute(ctx context.Context, req *unsafe.UnsafeReactivateAttributeRequest) (*unsafe.UnsafeReactivateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeReactivateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteAttribute(ctx context.Context, req *unsafe.UnsafeDeleteAttributeRequest) (*unsafe.UnsafeDeleteAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeUpdateAttributeValue(ctx context.Context, req *unsafe.UnsafeUpdateAttributeValueRequest) (*unsafe.UnsafeUpdateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeUpdateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeReactivateAttributeValue(ctx context.Context, req *unsafe.UnsafeReactivateAttributeValueRequest) (*unsafe.UnsafeReactivateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeReactivateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteAttributeValue(ctx context.Context, req *unsafe.UnsafeDeleteAttributeValueRequest) (*unsafe.UnsafeDeleteAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteKasKey(ctx context.Context, req *unsafe.UnsafeDeleteKasKeyRequest) (*unsafe.UnsafeDeleteKasKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteKasKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
