package realip

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"connectrpc.com/connect"
)

const (
	XRealIP       = "X-Real-IP"
	XForwardedFor = "X-Forwarded-For"
	TrueClientIP  = "True-Client-Ip"
)

type ClientIP struct{}

func ConnectRealIPUnaryInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			ip := getIP(ctx, req.Peer(), req.Header())

			ctx = context.WithValue(ctx, ClientIP{}, ip)

			return next(ctx, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

func getIP(_ context.Context, peer connect.Peer, headers http.Header) net.IP {
	for _, header := range []string{XRealIP, XForwardedFor, TrueClientIP} {
		if ip := headers.Get(header); ip != "" {
			ips := strings.Split(ip, ",")
			if ips[0] == "" || net.ParseIP(ips[0]) == nil {
				continue
			}
			return net.ParseIP(ips[0])
		}
	}

	ip, err := netip.ParseAddrPort(peer.Addr)
	if err != nil {
		return net.IP{}
	}

	return net.IP(ip.Addr().AsSlice())
}

func FromContext(ctx context.Context) net.IP {
	ip, ok := ctx.Value(ClientIP{}).(net.IP)
	if !ok {
		return net.IP{}
	}
	return ip
}
