// Wrapper for NamespaceServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
)

type NamespaceServiceClientConnectWrapper struct {
	namespacesconnect.NamespaceServiceClient
}

func NewNamespaceServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *NamespaceServiceClientConnectWrapper {
	return &NamespaceServiceClientConnectWrapper{NamespaceServiceClient: namespacesconnect.NewNamespaceServiceClient(httpClient, baseURL, opts...)}
}

type NamespaceServiceClient interface {
	GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest) (*namespaces.GetNamespaceResponse, error)
	ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error)
	CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error)
	UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error)
	DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest) (*namespaces.DeactivateNamespaceResponse, error)
	AssignKeyAccessServerToNamespace(ctx context.Context, req *namespaces.AssignKeyAccessServerToNamespaceRequest) (*namespaces.AssignKeyAccessServerToNamespaceResponse, error)
	RemoveKeyAccessServerFromNamespace(ctx context.Context, req *namespaces.RemoveKeyAccessServerFromNamespaceRequest) (*namespaces.RemoveKeyAccessServerFromNamespaceResponse, error)
	AssignPublicKeyToNamespace(ctx context.Context, req *namespaces.AssignPublicKeyToNamespaceRequest) (*namespaces.AssignPublicKeyToNamespaceResponse, error)
	RemovePublicKeyFromNamespace(ctx context.Context, req *namespaces.RemovePublicKeyFromNamespaceRequest) (*namespaces.RemovePublicKeyFromNamespaceResponse, error)
	AssignCertificateToNamespace(ctx context.Context, req *namespaces.AssignCertificateToNamespaceRequest) (*namespaces.AssignCertificateToNamespaceResponse, error)
	RemoveCertificateFromNamespace(ctx context.Context, req *namespaces.RemoveCertificateFromNamespaceRequest) (*namespaces.RemoveCertificateFromNamespaceResponse, error)
}

func (w *NamespaceServiceClientConnectWrapper) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest) (*namespaces.GetNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.GetNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.ListNamespaces(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.CreateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.UpdateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest) (*namespaces.DeactivateNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.DeactivateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) AssignKeyAccessServerToNamespace(ctx context.Context, req *namespaces.AssignKeyAccessServerToNamespaceRequest) (*namespaces.AssignKeyAccessServerToNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.AssignKeyAccessServerToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *namespaces.RemoveKeyAccessServerFromNamespaceRequest) (*namespaces.RemoveKeyAccessServerFromNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.RemoveKeyAccessServerFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) AssignPublicKeyToNamespace(ctx context.Context, req *namespaces.AssignPublicKeyToNamespaceRequest) (*namespaces.AssignPublicKeyToNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.AssignPublicKeyToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) RemovePublicKeyFromNamespace(ctx context.Context, req *namespaces.RemovePublicKeyFromNamespaceRequest) (*namespaces.RemovePublicKeyFromNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.RemovePublicKeyFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) AssignCertificateToNamespace(ctx context.Context, req *namespaces.AssignCertificateToNamespaceRequest) (*namespaces.AssignCertificateToNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.AssignCertificateToNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *NamespaceServiceClientConnectWrapper) RemoveCertificateFromNamespace(ctx context.Context, req *namespaces.RemoveCertificateFromNamespaceRequest) (*namespaces.RemoveCertificateFromNamespaceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.NamespaceServiceClient.RemoveCertificateFromNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
