// Wrapper for FeatureFlagServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/featureflag"
	"github.com/opentdf/platform/protocol/go/featureflag/featureflagconnect"
)

type FeatureFlagServiceClientConnectWrapper struct {
	featureflagconnect.FeatureFlagServiceClient
}

func NewFeatureFlagServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *FeatureFlagServiceClientConnectWrapper {
	return &FeatureFlagServiceClientConnectWrapper{FeatureFlagServiceClient: featureflagconnect.NewFeatureFlagServiceClient(httpClient, baseURL, opts...)}
}

type FeatureFlagServiceClient interface {
	ResolveAll(ctx context.Context, req *featureflag.ResolveAllRequest) (*featureflag.ResolveAllResponse, error)
	ResolveBoolean(ctx context.Context, req *featureflag.ResolveBooleanRequest) (*featureflag.ResolveBooleanResponse, error)
	ResolveString(ctx context.Context, req *featureflag.ResolveStringRequest) (*featureflag.ResolveStringResponse, error)
	ResolveFloat(ctx context.Context, req *featureflag.ResolveFloatRequest) (*featureflag.ResolveFloatResponse, error)
	ResolveInt(ctx context.Context, req *featureflag.ResolveIntRequest) (*featureflag.ResolveIntResponse, error)
	ResolveObject(ctx context.Context, req *featureflag.ResolveObjectRequest) (*featureflag.ResolveObjectResponse, error)
}

func (w *FeatureFlagServiceClientConnectWrapper) ResolveAll(ctx context.Context, req *featureflag.ResolveAllRequest) (*featureflag.ResolveAllResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.FeatureFlagServiceClient.ResolveAll(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *FeatureFlagServiceClientConnectWrapper) ResolveBoolean(ctx context.Context, req *featureflag.ResolveBooleanRequest) (*featureflag.ResolveBooleanResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.FeatureFlagServiceClient.ResolveBoolean(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *FeatureFlagServiceClientConnectWrapper) ResolveString(ctx context.Context, req *featureflag.ResolveStringRequest) (*featureflag.ResolveStringResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.FeatureFlagServiceClient.ResolveString(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *FeatureFlagServiceClientConnectWrapper) ResolveFloat(ctx context.Context, req *featureflag.ResolveFloatRequest) (*featureflag.ResolveFloatResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.FeatureFlagServiceClient.ResolveFloat(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *FeatureFlagServiceClientConnectWrapper) ResolveInt(ctx context.Context, req *featureflag.ResolveIntRequest) (*featureflag.ResolveIntResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.FeatureFlagServiceClient.ResolveInt(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *FeatureFlagServiceClientConnectWrapper) ResolveObject(ctx context.Context, req *featureflag.ResolveObjectRequest) (*featureflag.ResolveObjectResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.FeatureFlagServiceClient.ResolveObject(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
