// Wrapper for DynamicValueMappingServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping/dynamicvaluemappingconnect"
)

type DynamicValueMappingServiceClientConnectWrapper struct {
	dynamicvaluemappingconnect.DynamicValueMappingServiceClient
}

func NewDynamicValueMappingServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *DynamicValueMappingServiceClientConnectWrapper {
	return &DynamicValueMappingServiceClientConnectWrapper{DynamicValueMappingServiceClient: dynamicvaluemappingconnect.NewDynamicValueMappingServiceClient(httpClient, baseURL, opts...)}
}

type DynamicValueMappingServiceClient interface {
	ListDynamicValueMappings(ctx context.Context, req *dynamicvaluemapping.ListDynamicValueMappingsRequest) (*dynamicvaluemapping.ListDynamicValueMappingsResponse, error)
	GetDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.GetDynamicValueMappingRequest) (*dynamicvaluemapping.GetDynamicValueMappingResponse, error)
	CreateDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.CreateDynamicValueMappingRequest) (*dynamicvaluemapping.CreateDynamicValueMappingResponse, error)
	UpdateDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.UpdateDynamicValueMappingRequest) (*dynamicvaluemapping.UpdateDynamicValueMappingResponse, error)
	DeleteDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.DeleteDynamicValueMappingRequest) (*dynamicvaluemapping.DeleteDynamicValueMappingResponse, error)
}

func (w *DynamicValueMappingServiceClientConnectWrapper) ListDynamicValueMappings(ctx context.Context, req *dynamicvaluemapping.ListDynamicValueMappingsRequest) (*dynamicvaluemapping.ListDynamicValueMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DynamicValueMappingServiceClient.ListDynamicValueMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DynamicValueMappingServiceClientConnectWrapper) GetDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.GetDynamicValueMappingRequest) (*dynamicvaluemapping.GetDynamicValueMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DynamicValueMappingServiceClient.GetDynamicValueMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DynamicValueMappingServiceClientConnectWrapper) CreateDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.CreateDynamicValueMappingRequest) (*dynamicvaluemapping.CreateDynamicValueMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DynamicValueMappingServiceClient.CreateDynamicValueMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DynamicValueMappingServiceClientConnectWrapper) UpdateDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.UpdateDynamicValueMappingRequest) (*dynamicvaluemapping.UpdateDynamicValueMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DynamicValueMappingServiceClient.UpdateDynamicValueMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DynamicValueMappingServiceClientConnectWrapper) DeleteDynamicValueMapping(ctx context.Context, req *dynamicvaluemapping.DeleteDynamicValueMappingRequest) (*dynamicvaluemapping.DeleteDynamicValueMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DynamicValueMappingServiceClient.DeleteDynamicValueMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
