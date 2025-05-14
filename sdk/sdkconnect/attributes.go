// Wrapper for AttributesServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"context"
	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"

)

type AttributesServiceClientConnectWrapper struct {
	attributesconnect.AttributesServiceClient
}

func NewAttributesServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *AttributesServiceClientConnectWrapper {
	return &AttributesServiceClientConnectWrapper{AttributesServiceClient: attributesconnect.NewAttributesServiceClient(httpClient, baseURL, opts...)}
}

func (w *AttributesServiceClientConnectWrapper) ListAttributes(ctx context.Context, req *attributes.ListAttributesRequest, _ ...grpc.CallOption) (*attributes.ListAttributesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.ListAttributes(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest, _ ...grpc.CallOption) (*attributes.ListAttributeValuesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.ListAttributeValues(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) GetAttribute(ctx context.Context, req *attributes.GetAttributeRequest, _ ...grpc.CallOption) (*attributes.GetAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.GetAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) GetAttributeValuesByFqns(ctx context.Context, req *attributes.GetAttributeValuesByFqnsRequest, _ ...grpc.CallOption) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.GetAttributeValuesByFqns(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) CreateAttribute(ctx context.Context, req *attributes.CreateAttributeRequest, _ ...grpc.CallOption) (*attributes.CreateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.CreateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) UpdateAttribute(ctx context.Context, req *attributes.UpdateAttributeRequest, _ ...grpc.CallOption) (*attributes.UpdateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.UpdateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) DeactivateAttribute(ctx context.Context, req *attributes.DeactivateAttributeRequest, _ ...grpc.CallOption) (*attributes.DeactivateAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.DeactivateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest, _ ...grpc.CallOption) (*attributes.GetAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.GetAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest, _ ...grpc.CallOption) (*attributes.CreateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.CreateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest, _ ...grpc.CallOption) (*attributes.UpdateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.UpdateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest, _ ...grpc.CallOption) (*attributes.DeactivateAttributeValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.DeactivateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest, _ ...grpc.CallOption) (*attributes.AssignKeyAccessServerToAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignKeyAccessServerToAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest, _ ...grpc.CallOption) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemoveKeyAccessServerFromAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest, _ ...grpc.CallOption) (*attributes.AssignKeyAccessServerToValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignKeyAccessServerToValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest, _ ...grpc.CallOption) (*attributes.RemoveKeyAccessServerFromValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemoveKeyAccessServerFromValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignPublicKeyToAttribute(ctx context.Context, req *attributes.AssignPublicKeyToAttributeRequest, _ ...grpc.CallOption) (*attributes.AssignPublicKeyToAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignPublicKeyToAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemovePublicKeyFromAttribute(ctx context.Context, req *attributes.RemovePublicKeyFromAttributeRequest, _ ...grpc.CallOption) (*attributes.RemovePublicKeyFromAttributeResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemovePublicKeyFromAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) AssignPublicKeyToValue(ctx context.Context, req *attributes.AssignPublicKeyToValueRequest, _ ...grpc.CallOption) (*attributes.AssignPublicKeyToValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.AssignPublicKeyToValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AttributesServiceClientConnectWrapper) RemovePublicKeyFromValue(ctx context.Context, req *attributes.RemovePublicKeyFromValueRequest, _ ...grpc.CallOption) (*attributes.RemovePublicKeyFromValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AttributesServiceClient.RemovePublicKeyFromValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
