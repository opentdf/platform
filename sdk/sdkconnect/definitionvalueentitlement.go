// Wrapper for DefinitionValueEntitlementMappingServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/definitionvalueentitlement"
	"github.com/opentdf/platform/protocol/go/policy/definitionvalueentitlement/definitionvalueentitlementconnect"
)

type DefinitionValueEntitlementMappingServiceClientConnectWrapper struct {
	definitionvalueentitlementconnect.DefinitionValueEntitlementMappingServiceClient
}

func NewDefinitionValueEntitlementMappingServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *DefinitionValueEntitlementMappingServiceClientConnectWrapper {
	return &DefinitionValueEntitlementMappingServiceClientConnectWrapper{DefinitionValueEntitlementMappingServiceClient: definitionvalueentitlementconnect.NewDefinitionValueEntitlementMappingServiceClient(httpClient, baseURL, opts...)}
}

type DefinitionValueEntitlementMappingServiceClient interface {
	ListDefinitionValueEntitlementMappings(ctx context.Context, req *definitionvalueentitlement.ListDefinitionValueEntitlementMappingsRequest) (*definitionvalueentitlement.ListDefinitionValueEntitlementMappingsResponse, error)
	GetDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.GetDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.GetDefinitionValueEntitlementMappingResponse, error)
	CreateDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.CreateDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.CreateDefinitionValueEntitlementMappingResponse, error)
	UpdateDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.UpdateDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.UpdateDefinitionValueEntitlementMappingResponse, error)
	DeleteDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.DeleteDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.DeleteDefinitionValueEntitlementMappingResponse, error)
}

func (w *DefinitionValueEntitlementMappingServiceClientConnectWrapper) ListDefinitionValueEntitlementMappings(ctx context.Context, req *definitionvalueentitlement.ListDefinitionValueEntitlementMappingsRequest) (*definitionvalueentitlement.ListDefinitionValueEntitlementMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DefinitionValueEntitlementMappingServiceClient.ListDefinitionValueEntitlementMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DefinitionValueEntitlementMappingServiceClientConnectWrapper) GetDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.GetDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.GetDefinitionValueEntitlementMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DefinitionValueEntitlementMappingServiceClient.GetDefinitionValueEntitlementMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DefinitionValueEntitlementMappingServiceClientConnectWrapper) CreateDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.CreateDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.CreateDefinitionValueEntitlementMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DefinitionValueEntitlementMappingServiceClient.CreateDefinitionValueEntitlementMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DefinitionValueEntitlementMappingServiceClientConnectWrapper) UpdateDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.UpdateDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.UpdateDefinitionValueEntitlementMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DefinitionValueEntitlementMappingServiceClient.UpdateDefinitionValueEntitlementMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *DefinitionValueEntitlementMappingServiceClientConnectWrapper) DeleteDefinitionValueEntitlementMapping(ctx context.Context, req *definitionvalueentitlement.DeleteDefinitionValueEntitlementMappingRequest) (*definitionvalueentitlement.DeleteDefinitionValueEntitlementMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.DefinitionValueEntitlementMappingServiceClient.DeleteDefinitionValueEntitlementMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
