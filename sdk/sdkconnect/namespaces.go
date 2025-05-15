// Wrapper for NamespaceServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"google.golang.org/grpc"
)

type NamespaceServiceClientConnectWrapper struct {
	namespacesconnect.NamespaceServiceClient
}

func NewNamespaceServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *NamespaceServiceClientConnectWrapper {
	return &NamespaceServiceClientConnectWrapper{NamespaceServiceClient: namespacesconnect.NewNamespaceServiceClient(httpClient, baseURL, opts...)}
}

func (w *NamespaceServiceClientConnectWrapper) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest, _ ...grpc.CallOption) (*namespaces.GetNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.GetNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest, _ ...grpc.CallOption) (*namespaces.ListNamespacesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.ListNamespaces(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest, _ ...grpc.CallOption) (*namespaces.CreateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.CreateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest, _ ...grpc.CallOption) (*namespaces.UpdateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.UpdateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest, _ ...grpc.CallOption) (*namespaces.DeactivateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.DeactivateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) AssignKeyAccessServerToNamespace(ctx context.Context, req *namespaces.AssignKeyAccessServerToNamespaceRequest, _ ...grpc.CallOption) (*namespaces.AssignKeyAccessServerToNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.AssignKeyAccessServerToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *namespaces.RemoveKeyAccessServerFromNamespaceRequest, _ ...grpc.CallOption) (*namespaces.RemoveKeyAccessServerFromNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.RemoveKeyAccessServerFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) AssignPublicKeyToNamespace(ctx context.Context, req *namespaces.AssignPublicKeyToNamespaceRequest, _ ...grpc.CallOption) (*namespaces.AssignPublicKeyToNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.AssignPublicKeyToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) RemovePublicKeyFromNamespace(ctx context.Context, req *namespaces.RemovePublicKeyFromNamespaceRequest, _ ...grpc.CallOption) (*namespaces.RemovePublicKeyFromNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.RemovePublicKeyFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
