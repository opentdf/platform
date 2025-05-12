package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnect"
	"google.golang.org/grpc"
)

// Unsafe Client
type UnsafeConnectClient struct {
	unsafeconnect.UnsafeServiceClient
}

func NewUnsafeConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) UnsafeConnectClient {
	return UnsafeConnectClient{
		UnsafeServiceClient: unsafeconnect.NewUnsafeServiceClient(httpClient, baseURL, opts...),
	}
}
func (c UnsafeConnectClient) UnsafeUpdateNamespace(ctx context.Context, req *unsafe.UnsafeUpdateNamespaceRequest, _ ...grpc.CallOption) (*unsafe.UnsafeUpdateNamespaceResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeUpdateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeReactivateNamespace(ctx context.Context, req *unsafe.UnsafeReactivateNamespaceRequest, _ ...grpc.CallOption) (*unsafe.UnsafeReactivateNamespaceResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeReactivateNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeDeleteNamespace(ctx context.Context, req *unsafe.UnsafeDeleteNamespaceRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteNamespaceResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeDeleteNamespace(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeUpdateAttribute(ctx context.Context, req *unsafe.UnsafeUpdateAttributeRequest, _ ...grpc.CallOption) (*unsafe.UnsafeUpdateAttributeResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeUpdateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeReactivateAttribute(ctx context.Context, req *unsafe.UnsafeReactivateAttributeRequest, _ ...grpc.CallOption) (*unsafe.UnsafeReactivateAttributeResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeReactivateAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeDeleteAttribute(ctx context.Context, req *unsafe.UnsafeDeleteAttributeRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteAttributeResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeDeleteAttribute(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeUpdateAttributeValue(ctx context.Context, req *unsafe.UnsafeUpdateAttributeValueRequest, _ ...grpc.CallOption) (*unsafe.UnsafeUpdateAttributeValueResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeUpdateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeReactivateAttributeValue(ctx context.Context, req *unsafe.UnsafeReactivateAttributeValueRequest, _ ...grpc.CallOption) (*unsafe.UnsafeReactivateAttributeValueResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeReactivateAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeDeleteAttributeValue(ctx context.Context, req *unsafe.UnsafeDeleteAttributeValueRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteAttributeValueResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeDeleteAttributeValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c UnsafeConnectClient) UnsafeDeleteKasKey(ctx context.Context, req *unsafe.UnsafeDeleteKasKeyRequest, _ ...grpc.CallOption) (*unsafe.UnsafeDeleteKasKeyResponse, error) {
	res, err := c.UnsafeServiceClient.UnsafeDeleteKasKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
