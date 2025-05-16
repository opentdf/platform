// Wrapper for AttributesServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
)

type AttributesServiceClientConnectWrapper struct {
	attributesconnect.AttributesServiceClient
}

func NewAttributesServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *AttributesServiceClientConnectWrapper {
	return &AttributesServiceClientConnectWrapper{AttributesServiceClient: attributesconnect.NewAttributesServiceClient(httpClient, baseURL, opts...)}
}

type AttributesServiceClient interface {
	ListAttributes(ctx context.Context, req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error)
	ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error)
	GetAttribute(ctx context.Context, req *attributes.GetAttributeRequest) (*attributes.GetAttributeResponse, error)
	GetAttributeValuesByFqns(ctx context.Context, req *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error)
	CreateAttribute(ctx context.Context, req *attributes.CreateAttributeRequest) (*attributes.CreateAttributeResponse, error)
	UpdateAttribute(ctx context.Context, req *attributes.UpdateAttributeRequest) (*attributes.UpdateAttributeResponse, error)
	DeactivateAttribute(ctx context.Context, req *attributes.DeactivateAttributeRequest) (*attributes.DeactivateAttributeResponse, error)
	GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest) (*attributes.GetAttributeValueResponse, error)
	CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest) (*attributes.CreateAttributeValueResponse, error)
	UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest) (*attributes.UpdateAttributeValueResponse, error)
	DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest) (*attributes.DeactivateAttributeValueResponse, error)
	AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest) (*attributes.AssignKeyAccessServerToAttributeResponse, error)
	RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error)
	AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest) (*attributes.AssignKeyAccessServerToValueResponse, error)
	RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest) (*attributes.RemoveKeyAccessServerFromValueResponse, error)
	AssignPublicKeyToAttribute(ctx context.Context, req *attributes.AssignPublicKeyToAttributeRequest) (*attributes.AssignPublicKeyToAttributeResponse, error)
	RemovePublicKeyFromAttribute(ctx context.Context, req *attributes.RemovePublicKeyFromAttributeRequest) (*attributes.RemovePublicKeyFromAttributeResponse, error)
	AssignPublicKeyToValue(ctx context.Context, req *attributes.AssignPublicKeyToValueRequest) (*attributes.AssignPublicKeyToValueResponse, error)
	RemovePublicKeyFromValue(ctx context.Context, req *attributes.RemovePublicKeyFromValueRequest) (*attributes.RemovePublicKeyFromValueResponse, error)
}

func (w *AttributesServiceClientConnectWrapper) ListAttributes(ctx context.Context, req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.ListAttributes(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.ListAttributeValues(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) GetAttribute(ctx context.Context, req *attributes.GetAttributeRequest) (*attributes.GetAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.GetAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) GetAttributeValuesByFqns(ctx context.Context, req *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.GetAttributeValuesByFqns(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) CreateAttribute(ctx context.Context, req *attributes.CreateAttributeRequest) (*attributes.CreateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.CreateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) UpdateAttribute(ctx context.Context, req *attributes.UpdateAttributeRequest) (*attributes.UpdateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.UpdateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) DeactivateAttribute(ctx context.Context, req *attributes.DeactivateAttributeRequest) (*attributes.DeactivateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.DeactivateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest) (*attributes.GetAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.GetAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest) (*attributes.CreateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.CreateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest) (*attributes.UpdateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.UpdateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest) (*attributes.DeactivateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.DeactivateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest) (*attributes.AssignKeyAccessServerToAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignKeyAccessServerToAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemoveKeyAccessServerFromAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest) (*attributes.AssignKeyAccessServerToValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignKeyAccessServerToValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest) (*attributes.RemoveKeyAccessServerFromValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemoveKeyAccessServerFromValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignPublicKeyToAttribute(ctx context.Context, req *attributes.AssignPublicKeyToAttributeRequest) (*attributes.AssignPublicKeyToAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignPublicKeyToAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemovePublicKeyFromAttribute(ctx context.Context, req *attributes.RemovePublicKeyFromAttributeRequest) (*attributes.RemovePublicKeyFromAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemovePublicKeyFromAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignPublicKeyToValue(ctx context.Context, req *attributes.AssignPublicKeyToValueRequest) (*attributes.AssignPublicKeyToValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignPublicKeyToValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemovePublicKeyFromValue(ctx context.Context, req *attributes.RemovePublicKeyFromValueRequest) (*attributes.RemovePublicKeyFromValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemovePublicKeyFromValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
