package realip

import (
	"context"
	"fmt"
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

type resolver struct {
	trustedProxies []netip.Prefix
}

// ConnectRealIPUnaryInterceptor resolves the client IP from the socket peer and,
// only when that peer is trusted, proxy forwarding headers.
func ConnectRealIPUnaryInterceptor(trustedProxyCIDRs []string) (connect.UnaryInterceptorFunc, error) {
	resolver, err := newResolver(trustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			ctx = context.WithValue(ctx, ClientIP{}, resolver.resolve(req.Peer(), req.Header()))
			return next(ctx, req)
		})
	}), nil
}

// ConnectTrustedRequestIPUnaryInterceptor accepts a single propagated IP from
// an in-process transport. It must not be installed on a public listener.
func ConnectTrustedRequestIPUnaryInterceptor(header string) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			ip := peerIP(req.Peer())
			if values := req.Header().Values(header); len(values) == 1 {
				if propagated, ok := parseIP(values[0]); ok {
					ip = propagated
				}
			}
			var clientIP net.IP
			if ip.IsValid() {
				clientIP = ip.AsSlice()
			}
			ctx = context.WithValue(ctx, ClientIP{}, clientIP)
			return next(ctx, req)
		})
	})
}

func newResolver(trustedProxyCIDRs []string) (*resolver, error) {
	trustedProxies := make([]netip.Prefix, 0, len(trustedProxyCIDRs))
	for _, cidr := range trustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		trustedProxies = append(trustedProxies, prefix.Masked())
	}
	return &resolver{trustedProxies: trustedProxies}, nil
}

func (r *resolver) resolve(peer connect.Peer, headers http.Header) net.IP {
	peerAddr := peerIP(peer)
	if !peerAddr.IsValid() {
		return nil
	}
	if !r.isTrusted(peerAddr) {
		return peerAddr.AsSlice()
	}

	if values := headers.Values(XForwardedFor); len(values) > 0 {
		parts := strings.Split(strings.Join(values, ","), ",")
		var leftmost netip.Addr
		for i := len(parts) - 1; i >= 0; i-- {
			ip, ok := parseIP(parts[i])
			if !ok {
				return peerAddr.AsSlice()
			}
			if !r.isTrusted(ip) {
				return ip.AsSlice()
			}
			leftmost = ip
		}
		return leftmost.AsSlice()
	}

	for _, header := range []string{XRealIP, TrueClientIP} {
		if values := headers.Values(header); len(values) > 0 {
			if len(values) != 1 {
				return peerAddr.AsSlice()
			}
			ip, ok := parseIP(values[0])
			if !ok {
				return peerAddr.AsSlice()
			}
			return ip.AsSlice()
		}
	}

	return peerAddr.AsSlice()
}

func (r *resolver) isTrusted(ip netip.Addr) bool {
	for _, prefix := range r.trustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func parseIP(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func peerIP(peer connect.Peer) netip.Addr {
	if addrPort, err := netip.ParseAddrPort(strings.TrimSpace(peer.Addr)); err == nil {
		return addrPort.Addr().Unmap()
	}
	ip, ok := parseIP(peer.Addr)
	if !ok {
		return netip.Addr{}
	}
	return ip
}

func FromContext(ctx context.Context) net.IP {
	ip, ok := ctx.Value(ClientIP{}).(net.IP)
	if !ok {
		return nil
	}
	return ip
}
