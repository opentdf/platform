// Wrapper for ServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/obligations/obligationsconnect"
)

type ServiceClientConnectWrapper struct {
	obligationsconnect.ServiceClient
}

func NewServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *ServiceClientConnectWrapper {
	return &ServiceClientConnectWrapper{ServiceClient: obligationsconnect.NewServiceClient(httpClient, baseURL, opts...)}
}

type ServiceClient interface {
	ListObligations(ctx context.Context, req *obligations.ListObligationsRequest) (*obligations.ListObligationsResponse, error)
	GetObligation(ctx context.Context, req *obligations.GetObligationRequest) (*obligations.GetObligationResponse, error)
	GetObligationsByFQNs(ctx context.Context, req *obligations.GetObligationsByFQNsRequest) (*obligations.GetObligationsByFQNsResponse, error)
	CreateObligation(ctx context.Context, req *obligations.CreateObligationRequest) (*obligations.CreateObligationResponse, error)
	UpdateObligation(ctx context.Context, req *obligations.UpdateObligationRequest) (*obligations.UpdateObligationResponse, error)
	DeleteObligation(ctx context.Context, req *obligations.DeleteObligationRequest) (*obligations.DeleteObligationResponse, error)
	GetObligationValue(ctx context.Context, req *obligations.GetObligationValueRequest) (*obligations.GetObligationValueResponse, error)
	GetObligationValuesByFQNs(ctx context.Context, req *obligations.GetObligationValuesByFQNsRequest) (*obligations.GetObligationValuesByFQNsResponse, error)
	CreateObligationValue(ctx context.Context, req *obligations.CreateObligationValueRequest) (*obligations.CreateObligationValueResponse, error)
	UpdateObligationValue(ctx context.Context, req *obligations.UpdateObligationValueRequest) (*obligations.UpdateObligationValueResponse, error)
	DeleteObligationValue(ctx context.Context, req *obligations.DeleteObligationValueRequest) (*obligations.DeleteObligationValueResponse, error)
	AddObligationTrigger(ctx context.Context, req *obligations.AddObligationTriggerRequest) (*obligations.AddObligationTriggerResponse, error)
	RemoveObligationTrigger(ctx context.Context, req *obligations.RemoveObligationTriggerRequest) (*obligations.RemoveObligationTriggerResponse, error)
}

func (w *ServiceClientConnectWrapper) ListObligations(ctx context.Context, req *obligations.ListObligationsRequest) (*obligations.ListObligationsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.ListObligations(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) GetObligation(ctx context.Context, req *obligations.GetObligationRequest) (*obligations.GetObligationResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.GetObligation(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) GetObligationsByFQNs(ctx context.Context, req *obligations.GetObligationsByFQNsRequest) (*obligations.GetObligationsByFQNsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.GetObligationsByFQNs(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) CreateObligation(ctx context.Context, req *obligations.CreateObligationRequest) (*obligations.CreateObligationResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.CreateObligation(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) UpdateObligation(ctx context.Context, req *obligations.UpdateObligationRequest) (*obligations.UpdateObligationResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.UpdateObligation(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) DeleteObligation(ctx context.Context, req *obligations.DeleteObligationRequest) (*obligations.DeleteObligationResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.DeleteObligation(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) GetObligationValue(ctx context.Context, req *obligations.GetObligationValueRequest) (*obligations.GetObligationValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.GetObligationValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) GetObligationValuesByFQNs(ctx context.Context, req *obligations.GetObligationValuesByFQNsRequest) (*obligations.GetObligationValuesByFQNsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.GetObligationValuesByFQNs(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) CreateObligationValue(ctx context.Context, req *obligations.CreateObligationValueRequest) (*obligations.CreateObligationValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.CreateObligationValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) UpdateObligationValue(ctx context.Context, req *obligations.UpdateObligationValueRequest) (*obligations.UpdateObligationValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.UpdateObligationValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) DeleteObligationValue(ctx context.Context, req *obligations.DeleteObligationValueRequest) (*obligations.DeleteObligationValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.DeleteObligationValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) AddObligationTrigger(ctx context.Context, req *obligations.AddObligationTriggerRequest) (*obligations.AddObligationTriggerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.AddObligationTrigger(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ServiceClientConnectWrapper) RemoveObligationTrigger(ctx context.Context, req *obligations.RemoveObligationTriggerRequest) (*obligations.RemoveObligationTriggerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ServiceClient.RemoveObligationTrigger(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
