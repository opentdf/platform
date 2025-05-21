// Wrapper for EntityResolutionServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"
)

type EntityResolutionServiceClientConnectWrapper struct {
	entityresolutionconnect.EntityResolutionServiceClient
}

func NewEntityResolutionServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *EntityResolutionServiceClientConnectWrapper {
	return &EntityResolutionServiceClientConnectWrapper{EntityResolutionServiceClient: entityresolutionconnect.NewEntityResolutionServiceClient(httpClient, baseURL, opts...)}
}

type EntityResolutionServiceClient interface {
	ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest) (*entityresolution.ResolveEntitiesResponse, error)
	CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest) (*entityresolution.CreateEntityChainFromJwtResponse, error)
}

func (w *EntityResolutionServiceClientConnectWrapper) ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest) (*entityresolution.ResolveEntitiesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.EntityResolutionServiceClient.ResolveEntities(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *EntityResolutionServiceClientConnectWrapper) CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.EntityResolutionServiceClient.CreateEntityChainFromJwt(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
