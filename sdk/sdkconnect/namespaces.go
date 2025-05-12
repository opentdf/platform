package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"google.golang.org/grpc"
)

// Namespaces Client
type NamespacesConnectClient struct {
	namespacesconnect.NamespaceServiceClient
}

func NewNamespacesConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) NamespacesConnectClient {
	return NamespacesConnectClient{
		NamespaceServiceClient: namespacesconnect.NewNamespaceServiceClient(httpClient, baseURL, opts...),
	}
}
func (c NamespacesConnectClient) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest, _ ...grpc.CallOption) (*namespaces.GetNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.GetNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest, _ ...grpc.CallOption) (*namespaces.ListNamespacesResponse, error) {
	res, err := c.NamespaceServiceClient.ListNamespaces(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest, _ ...grpc.CallOption) (*namespaces.CreateNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.CreateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest, _ ...grpc.CallOption) (*namespaces.UpdateNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.UpdateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest, _ ...grpc.CallOption) (*namespaces.DeactivateNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.DeactivateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) AssignKeyAccessServerToNamespace(ctx context.Context, req *namespaces.AssignKeyAccessServerToNamespaceRequest, _ ...grpc.CallOption) (*namespaces.AssignKeyAccessServerToNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.AssignKeyAccessServerToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *namespaces.RemoveKeyAccessServerFromNamespaceRequest, _ ...grpc.CallOption) (*namespaces.RemoveKeyAccessServerFromNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.RemoveKeyAccessServerFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) AssignPublicKeyToNamespace(ctx context.Context, req *namespaces.AssignPublicKeyToNamespaceRequest, _ ...grpc.CallOption) (*namespaces.AssignPublicKeyToNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.AssignPublicKeyToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c NamespacesConnectClient) RemovePublicKeyFromNamespace(ctx context.Context, req *namespaces.RemovePublicKeyFromNamespaceRequest, _ ...grpc.CallOption) (*namespaces.RemovePublicKeyFromNamespaceResponse, error) {
	res, err := c.NamespaceServiceClient.RemovePublicKeyFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
