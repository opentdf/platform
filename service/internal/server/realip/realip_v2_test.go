package realip

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const realIPTestProcedure = "/realip.test.v1.RealIPService/Call"

// callWithClientIP serves interceptor on a loopback listener and returns the
// client IP the handler sees for a request carrying header.
func callWithClientIP(t *testing.T, interceptor connectv2.ServerInterceptor, header http.Header) net.IP {
	t.Helper()
	var got net.IP
	server := connectv2.NewServer(interceptor)
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: realIPTestProcedure, StreamType: connectv2.StreamTypeUnary},
		Handler: func(ctx context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			got = FromContext(ctx)
			return stream.Send(&emptypb.Empty{})
		},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), srv.URL+realIPTestProcedure)
	req := connect.NewRequest(&emptypb.Empty{})
	for key, values := range header {
		for _, value := range values {
			req.Header().Add(key, value)
		}
	}
	_, err := client.CallUnary(t.Context(), req)
	require.NoError(t, err)
	return got
}

func TestConnectRealIPInterceptorV2(t *testing.T) {
	forwarded := http.Header{}
	forwarded.Set(XForwardedFor, "203.0.113.10")

	untrusted, err := ConnectRealIPInterceptorV2(nil)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", callWithClientIP(t, untrusted, forwarded).String(), "an untrusted peer cannot forward an address")

	trusted, err := ConnectRealIPInterceptorV2([]string{"127.0.0.0/8"})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.10", callWithClientIP(t, trusted, forwarded).String())

	_, err = ConnectRealIPInterceptorV2([]string{"not-a-cidr"})
	require.Error(t, err)
}

func TestConnectTrustedRequestIPInterceptorV2(t *testing.T) {
	const header = "X-Request-Ip"
	propagated := http.Header{}
	propagated.Set(header, "198.51.100.7")

	interceptor := ConnectTrustedRequestIPInterceptorV2(header)

	assert.Equal(t, "198.51.100.7", callWithClientIP(t, interceptor, propagated).String())
	assert.Equal(t, "127.0.0.1", callWithClientIP(t, interceptor, nil).String())
}
