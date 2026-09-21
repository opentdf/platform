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
	_, err := newResolver([]string{"", "not-a-cidr"})
	require.ErrorContains(t, err, "invalid trusted proxy CIDR")
}

func TestNewResolverIgnoresBlankEntries(t *testing.T) {
	r, err := newResolver([]string{"", " 10.0.0.0/8 ", " \t"})
	require.NoError(t, err)
	require.Len(t, r.trustedProxies, 1)
	assert.Equal(t, "10.0.0.0/8", r.trustedProxies[0].String())

	r, err = newResolver([]string{"", " "})
	require.NoError(t, err)
	assert.Empty(t, r.trustedProxies)
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
			name:           "trusted peer accepts IPv4 with port",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"203.0.113.10:5555"}},
			want:           "203.0.113.10",
		},
		{
			name:           "trusted peer accepts IPv6 with port",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"[2001:db8::1]:5555"}},
			want:           "2001:db8::1",
		},
		{
			name:           "invalid forwarded port falls back to peer",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"203.0.113.10:65536"}},
			want:           "10.0.0.3",
		},
		{
			name:           "trusted chain with ports ignores spoofed prefix",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"unknown, 203.0.113.10:5555, 10.0.0.2:443"}},
			want:           "203.0.113.10",
		},
		{
			name:           "Google frontend address must also be trusted",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"203.0.113.10, 192.0.2.20"}},
			want:           "192.0.2.20",
		},
		{
			name:           "Google chain skips configured frontend address",
			trustedProxies: []string{"10.0.0.0/8", "192.0.2.20/32"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{XForwardedFor: []string{"unknown, 203.0.113.10, 192.0.2.20"}},
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
			name:           "trusted peer does not trust alternate client IP headers",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers: http.Header{
				XRealIP:      []string{"203.0.113.10"},
				TrueClientIP: []string{"203.0.113.11"},
			},
			want: "10.0.0.3",
		},
		{
			name:           "trusted peer does not trust True-Client-IP alone",
			trustedProxies: []string{"10.0.0.0/8"},
			peer:           "10.0.0.3:1234",
			headers:        http.Header{TrueClientIP: []string{"203.0.113.10"}},
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

func TestParseForwardedIP(t *testing.T) {
	for _, value := range []string{"2001:db8::1", " [2001:db8::1]:5555 "} {
		ip, ok := parseForwardedIP(value)
		require.True(t, ok, value)
		assert.Equal(t, "2001:db8::1", ip.String())
	}
	ip, ok := parseForwardedIP("[::ffff:203.0.113.10]:5555")
	require.True(t, ok)
	assert.Equal(t, "203.0.113.10", ip.String())

	for _, value := range []string{
		"203.0.113.10:65536", "203.0.113.10:http", "203.0.113.10:",
		"example.com:443", "[fe80::1%eth0]:5555", "fe80::1%eth0", "",
	} {
		_, valid := parseForwardedIP(value)
		assert.False(t, valid, value)
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
