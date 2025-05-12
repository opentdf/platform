package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"google.golang.org/grpc"
)

// WellKnownConfiguration Client
type WellKnownConfigurationConnectClient struct {
	wellknownconfigurationconnect.WellKnownServiceClient
}

func NewWellKnownConfigurationConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) WellKnownConfigurationConnectClient {
	return WellKnownConfigurationConnectClient{
		WellKnownServiceClient: wellknownconfigurationconnect.NewWellKnownServiceClient(httpClient, baseURL, opts...),
	}
}

func (c WellKnownConfigurationConnectClient) GetWellKnownConfiguration(ctx context.Context, req *wellknownconfiguration.GetWellKnownConfigurationRequest, _ ...grpc.CallOption) (*wellknownconfiguration.GetWellKnownConfigurationResponse, error) {
	res, err := c.WellKnownServiceClient.GetWellKnownConfiguration(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
