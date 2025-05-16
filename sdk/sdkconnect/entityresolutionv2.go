// Wrapper for EntityResolutionServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution/v2/entityresolutionv2connect"
)

type EntityResolutionServiceClientV2ConnectWrapper struct {
	entityresolutionv2connect.EntityResolutionServiceClient
}

func NewEntityResolutionServiceClientV2ConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *EntityResolutionServiceClientV2ConnectWrapper {
	return &EntityResolutionServiceClientV2ConnectWrapper{EntityResolutionServiceClient: entityresolutionv2connect.NewEntityResolutionServiceClient(httpClient, baseURL, opts...)}
}

type EntityResolutionServiceClientV2 interface {
	ResolveEntities(ctx context.Context, req *entityresolutionv2.ResolveEntitiesRequest) (*entityresolutionv2.ResolveEntitiesResponse, error)
	CreateEntityChainsFromTokens(ctx context.Context, req *entityresolutionv2.CreateEntityChainsFromTokensRequest) (*entityresolutionv2.CreateEntityChainsFromTokensResponse, error)
}

func (w *EntityResolutionServiceClientV2ConnectWrapper) ResolveEntities(ctx context.Context, req *entityresolutionv2.ResolveEntitiesRequest) (*entityresolutionv2.ResolveEntitiesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.EntityResolutionServiceClient.ResolveEntities(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *EntityResolutionServiceClientV2ConnectWrapper) CreateEntityChainsFromTokens(ctx context.Context, req *entityresolutionv2.CreateEntityChainsFromTokensRequest) (*entityresolutionv2.CreateEntityChainsFromTokensResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.EntityResolutionServiceClient.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
