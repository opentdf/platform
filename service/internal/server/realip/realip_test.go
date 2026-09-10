package realip

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResolverRejectsInvalidCIDR(t *testing.T) {
	_, err := newResolver([]string{"not-a-cidr"})
	require.ErrorContains(t, err, "invalid trusted proxy CIDR")
}

func TestResolver(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		peer           string
		headers        http.Header
		want           string
	}{
		{
			name: "direct IPv4 peer",
			peer: "127.0.0.1:1234",
			want: "127.0.0.1",
		},
		{
			name: "direct IPv6 peer",
			peer: "[::1]:1234",
			want: "::1",
		},
		{
			name: "IPv4-mapped peer is normalized",
			peer: "[::ffff:192.0.2.10]:1234",
			want: "192.0.2.10",
		},
		{
			name: "untrusted peer cannot spoof forwarding headers",
			peer: "192.0.2.10:1234",
			headers: http.Header{
				XForwardedFor: []string{"203.0.113.10"},
				XRealIP:       []string{"203.0.113.11"},
				TrueClientIP:  []string{"203.0.113.12"},
			},
			want: "192.0.2.10",
		},
		{
			name:           "trusted peer accepts one forwarded client",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"203.0.113.10"}},
			want:           "203.0.113.10",
		},
		{
			name:           "trusted proxy chain resolves from the right",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"198.51.100.20, 203.0.113.10, 10.0.0.2"}},
			want:           "203.0.113.10",
		},
		{
			name:           "multiple forwarded header lines form one chain",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"203.0.113.10", "10.0.0.2"}},
			want:           "203.0.113.10",
		},
		{
			name:           "all-trusted chain uses originating hop",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"10.0.0.1, 10.0.0.2"}},
			want:           "10.0.0.1",
		},
		{
			name:           "malformed forwarded chain falls back to peer",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"203.0.113.10, unknown"}},
			want:           "10.0.0.3",
		},
		{
			name:           "malformed untrusted prefix cannot erase resolved client",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"unknown, 198.51.100.20"}},
			want:           "198.51.100.20",
		},
		{
			name:           "malformed forwarded chain does not fall through",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers: http.Header{
				XForwardedFor: []string{"unknown"},
				XRealIP:       []string{"203.0.113.10"},
			},
			want: "10.0.0.3",
		},
		{
			name:           "trusted peer accepts real IP fallback",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XRealIP: []string{"203.0.113.10"}},
			want:           "203.0.113.10",
		},
		{
			name:           "duplicate single-IP header falls back to peer",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XRealIP: []string{"203.0.113.10", "203.0.113.11"}},
			want:           "10.0.0.3",
		},
		{
			name: "invalid peer is unresolved",
			peer: "not-an-address",
			want: "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := newResolver(tt.trustedProxies)
			require.NoError(t, err)
			headers := make(http.Header)
			for name, values := range tt.headers {
				for _, value := range values {
					headers.Add(name, value)
				}
			}
			assert.Equal(t, tt.want, resolver.resolve(connect.Peer{Addr: tt.peer}, headers).String())
		})
	}
}

func TestConnectTrustedRequestIPUnaryInterceptor(t *testing.T) {
	interceptor := ConnectTrustedRequestIPUnaryInterceptor("X-Propagated-Ip")

	var got string
	next := interceptor(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		got = FromContext(ctx).String()
		return nil, nil //nolint:nilnil // response is irrelevant to context propagation
	})
	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-Propagated-Ip", "203.0.113.10")
	_, err := next(t.Context(), req)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.10", got)
}
