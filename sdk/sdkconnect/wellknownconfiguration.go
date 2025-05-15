// Wrapper for WellKnownServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"google.golang.org/grpc"
)

type WellKnownServiceClientConnectWrapper struct {
	wellknownconfigurationconnect.WellKnownServiceClient
}

func NewWellKnownServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *WellKnownServiceClientConnectWrapper {
	return &WellKnownServiceClientConnectWrapper{WellKnownServiceClient: wellknownconfigurationconnect.NewWellKnownServiceClient(httpClient, baseURL, opts...)}
}

func (w *WellKnownServiceClientConnectWrapper) GetWellKnownConfiguration(ctx context.Context, req *wellknownconfiguration.GetWellKnownConfigurationRequest, _ ...grpc.CallOption) (*wellknownconfiguration.GetWellKnownConfigurationResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.WellKnownServiceClient.GetWellKnownConfiguration(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
