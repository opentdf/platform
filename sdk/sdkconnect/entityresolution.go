// Wrapper for EntityResolutionServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"context"
	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"

)

type EntityResolutionServiceClientConnectWrapper struct {
	entityresolutionconnect.EntityResolutionServiceClient
}

func NewEntityResolutionServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *EntityResolutionServiceClientConnectWrapper {
	return &EntityResolutionServiceClientConnectWrapper{EntityResolutionServiceClient: entityresolutionconnect.NewEntityResolutionServiceClient(httpClient, baseURL, opts...)}
}

func (w *EntityResolutionServiceClientConnectWrapper) ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest, _ ...grpc.CallOption) (*entityresolution.ResolveEntitiesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.EntityResolutionServiceClient.ResolveEntities(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *EntityResolutionServiceClientConnectWrapper) CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest, _ ...grpc.CallOption) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.EntityResolutionServiceClient.CreateEntityChainFromJwt(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
