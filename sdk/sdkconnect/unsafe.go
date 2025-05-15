// Wrapper for UnsafeServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnect"
	"google.golang.org/grpc"
)

type UnsafeServiceClientConnectWrapper struct {
	unsafeconnect.UnsafeServiceClient
}

func NewUnsafeServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *UnsafeServiceClientConnectWrapper {
	return &UnsafeServiceClientConnectWrapper{UnsafeServiceClient: unsafeconnect.NewUnsafeServiceClient(httpClient, baseURL, opts...)}
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeUpdateNamespace(ctx context.Context, req *unsafe.UnsafeUpdateNamespaceRequest, _ ...grpc.CallOption) (*unsafe.UnsafeUpdateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeUpdateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeReactivateNamespace(ctx context.Context, req *unsafe.UnsafeReactivateNamespaceRequest, _ ...grpc.CallOption) (*unsafe.UnsafeReactivateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeReactivateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteNamespace(ctx context.Context, req *unsafe.UnsafeDeleteNamespaceRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeUpdateAttribute(ctx context.Context, req *unsafe.UnsafeUpdateAttributeRequest, _ ...grpc.CallOption) (*unsafe.UnsafeUpdateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeUpdateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeReactivateAttribute(ctx context.Context, req *unsafe.UnsafeReactivateAttributeRequest, _ ...grpc.CallOption) (*unsafe.UnsafeReactivateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeReactivateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteAttribute(ctx context.Context, req *unsafe.UnsafeDeleteAttributeRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeUpdateAttributeValue(ctx context.Context, req *unsafe.UnsafeUpdateAttributeValueRequest, _ ...grpc.CallOption) (*unsafe.UnsafeUpdateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeUpdateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeReactivateAttributeValue(ctx context.Context, req *unsafe.UnsafeReactivateAttributeValueRequest, _ ...grpc.CallOption) (*unsafe.UnsafeReactivateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeReactivateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteAttributeValue(ctx context.Context, req *unsafe.UnsafeDeleteAttributeValueRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *UnsafeServiceClientConnectWrapper) UnsafeDeleteKasKey(ctx context.Context, req *unsafe.UnsafeDeleteKasKeyRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteKasKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.UnsafeServiceClient.UnsafeDeleteKasKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
