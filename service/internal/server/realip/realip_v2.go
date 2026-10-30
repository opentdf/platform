package realip

import (
	"context"

	connectv2 "connectrpc.com/connect/v2"
	"github.com/opentdf/platform/service/internal/connectcompat"
)

// ConnectRealIPInterceptorV2 is ConnectRealIPUnaryInterceptor for connect-go v2
// servers.
func ConnectRealIPInterceptorV2(trustedProxyCIDRs []string) (connectv2.ServerInterceptor, error) {
	resolver, err := newResolver(trustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			ctx = context.WithValue(ctx, ClientIP{}, resolver.resolve(peerAddr(ctx), connectcompat.RequestHeader(ctx)))
			return next(ctx, spec, stream)
		}
	}, nil
}

// ConnectTrustedRequestIPInterceptorV2 is ConnectTrustedRequestIPUnaryInterceptor
// for connect-go v2 servers. It must not be installed on a public listener.
func ConnectTrustedRequestIPInterceptorV2(header string) connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			ctx = context.WithValue(ctx, ClientIP{}, trustedRequestIP(peerAddr(ctx), connectcompat.RequestHeader(ctx).Values(header)))
			return next(ctx, spec, stream)
		}
	}
}

func peerAddr(ctx context.Context) string {
	if info, ok := connectv2.CallInfoForServerContext(ctx); ok {
		return info.PeerAddr
	}
	return ""
}
