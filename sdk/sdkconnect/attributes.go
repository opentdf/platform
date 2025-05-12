package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
	"google.golang.org/grpc"
)

type AttributesConnectClient struct {
	attributesconnect.AttributesServiceClient
}

func NewAttributesConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) AttributesConnectClient {
	return AttributesConnectClient{
		AttributesServiceClient: attributesconnect.NewAttributesServiceClient(httpClient, baseURL, opts...),
	}
}

func (c AttributesConnectClient) ListAttributes(ctx context.Context, req *attributes.ListAttributesRequest, _ ...grpc.CallOption) (*attributes.ListAttributesResponse, error) {
	res, err := c.AttributesServiceClient.ListAttributes(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) GetAttribute(ctx context.Context, req *attributes.GetAttributeRequest, _ ...grpc.CallOption) (*attributes.GetAttributeResponse, error) {
	res, err := c.AttributesServiceClient.GetAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) CreateAttribute(ctx context.Context, req *attributes.CreateAttributeRequest, _ ...grpc.CallOption) (*attributes.CreateAttributeResponse, error) {
	res, err := c.AttributesServiceClient.CreateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) UpdateAttribute(ctx context.Context, req *attributes.UpdateAttributeRequest, _ ...grpc.CallOption) (*attributes.UpdateAttributeResponse, error) {
	res, err := c.AttributesServiceClient.UpdateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) UpdateAttributeValue(ctx context.Context, req *attributes.UpdateAttributeValueRequest, _ ...grpc.CallOption) (*attributes.UpdateAttributeValueResponse, error) {
	res, err := c.AttributesServiceClient.UpdateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) DeactivateAttribute(ctx context.Context, req *attributes.DeactivateAttributeRequest, _ ...grpc.CallOption) (*attributes.DeactivateAttributeResponse, error) {
	res, err := c.AttributesServiceClient.DeactivateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) DeactivateAttributeValue(ctx context.Context, req *attributes.DeactivateAttributeValueRequest, _ ...grpc.CallOption) (*attributes.DeactivateAttributeValueResponse, error) {
	res, err := c.AttributesServiceClient.DeactivateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) ListAttributeValues(ctx context.Context, req *attributes.ListAttributeValuesRequest, _ ...grpc.CallOption) (*attributes.ListAttributeValuesResponse, error) {
	res, err := c.AttributesServiceClient.ListAttributeValues(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) GetAttributeValuesByFqns(ctx context.Context, req *attributes.GetAttributeValuesByFqnsRequest, _ ...grpc.CallOption) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	res, err := c.AttributesServiceClient.GetAttributeValuesByFqns(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) CreateAttributeValue(ctx context.Context, req *attributes.CreateAttributeValueRequest, _ ...grpc.CallOption) (*attributes.CreateAttributeValueResponse, error) {
	res, err := c.AttributesServiceClient.CreateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) AssignKeyAccessServerToAttribute(ctx context.Context, req *attributes.AssignKeyAccessServerToAttributeRequest, _ ...grpc.CallOption) (*attributes.AssignKeyAccessServerToAttributeResponse, error) {
	res, err := c.AttributesServiceClient.AssignKeyAccessServerToAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, req *attributes.RemoveKeyAccessServerFromAttributeRequest, _ ...grpc.CallOption) (*attributes.RemoveKeyAccessServerFromAttributeResponse, error) {
	res, err := c.AttributesServiceClient.RemoveKeyAccessServerFromAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) AssignKeyAccessServerToValue(ctx context.Context, req *attributes.AssignKeyAccessServerToValueRequest, _ ...grpc.CallOption) (*attributes.AssignKeyAccessServerToValueResponse, error) {
	res, err := c.AttributesServiceClient.AssignKeyAccessServerToValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) RemoveKeyAccessServerFromValue(ctx context.Context, req *attributes.RemoveKeyAccessServerFromValueRequest, _ ...grpc.CallOption) (*attributes.RemoveKeyAccessServerFromValueResponse, error) {
	res, err := c.AttributesServiceClient.RemoveKeyAccessServerFromValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) AssignPublicKeyToAttribute(ctx context.Context, req *attributes.AssignPublicKeyToAttributeRequest, _ ...grpc.CallOption) (*attributes.AssignPublicKeyToAttributeResponse, error) {
	res, err := c.AttributesServiceClient.AssignPublicKeyToAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) RemovePublicKeyFromAttribute(ctx context.Context, req *attributes.RemovePublicKeyFromAttributeRequest, _ ...grpc.CallOption) (*attributes.RemovePublicKeyFromAttributeResponse, error) {
	res, err := c.AttributesServiceClient.RemovePublicKeyFromAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) AssignPublicKeyToValue(ctx context.Context, req *attributes.AssignPublicKeyToValueRequest, _ ...grpc.CallOption) (*attributes.AssignPublicKeyToValueResponse, error) {
	res, err := c.AttributesServiceClient.AssignPublicKeyToValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) RemovePublicKeyFromValue(ctx context.Context, req *attributes.RemovePublicKeyFromValueRequest, _ ...grpc.CallOption) (*attributes.RemovePublicKeyFromValueResponse, error) {
	res, err := c.AttributesServiceClient.RemovePublicKeyFromValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c AttributesConnectClient) GetAttributeValue(ctx context.Context, req *attributes.GetAttributeValueRequest, _ ...grpc.CallOption) (*attributes.GetAttributeValueResponse, error) {
	res, err := c.AttributesServiceClient.GetAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
