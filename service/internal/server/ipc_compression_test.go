package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const ipcCompressionTestProcedure = "/test.v1.TransportService/Echo"

type encodingCapture struct {
	handler http.Handler

	mu                      sync.Mutex
	requestAcceptEncoding   string
	requestContentEncoding  string
	responseContentEncoding string
	responseBodyBytes       atomic.Int64
}

func (c *encodingCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	captureWriter := &encodingCaptureWriter{ResponseWriter: writer, bytes: &c.responseBodyBytes}
	c.handler.ServeHTTP(captureWriter, request)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestAcceptEncoding = request.Header.Get("Accept-Encoding")
	c.requestContentEncoding = request.Header.Get("Content-Encoding")
	c.responseContentEncoding = captureWriter.Header().Get("Content-Encoding")
}

func (c *encodingCapture) encodings() (string, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestAcceptEncoding, c.requestContentEncoding, c.responseContentEncoding
}

type encodingCaptureWriter struct {
	http.ResponseWriter
	bytes *atomic.Int64
}

func (w *encodingCaptureWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.bytes.Add(int64(n))
	return n, err
}

func echoHandler(options ...connect.HandlerOption) http.Handler {
	return connect.NewUnaryHandler(
		ipcCompressionTestProcedure,
		func(_ context.Context, request *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
			switch request.Msg.GetValue() {
			case "error":
				connectErr := connect.NewError(connect.CodeInvalidArgument, errors.New("requested error"))
				detail, err := connect.NewErrorDetail(&wrapperspb.StringValue{Value: "requested error detail"})
				if err != nil {
					return nil, err
				}
				connectErr.AddDetail(detail)
				return nil, connectErr
			case "large-response":
				return connect.NewResponse(&wrapperspb.StringValue{Value: strings.Repeat("response", 128)}), nil
			default:
				return connect.NewResponse(&wrapperspb.StringValue{Value: request.Msg.GetValue()}), nil
			}
		},
		options...,
	)
}

func newIPCCompressionTestClient(tb testing.TB, disableCompression bool, handler http.Handler) (*memhttp.Server, *encodingCapture, *sdk.ConnectRPCConnection, *connect.Client[wrapperspb.StringValue, wrapperspb.StringValue]) {
	tb.Helper()
	return newIPCCompressionTestClientWithLimits(tb, disableCompression, handler, 4*1024*1024, 4*1024*1024)
}

func newIPCCompressionTestClientWithLimits(tb testing.TB, disableCompression bool, handler http.Handler, readMaxBytes, sendMaxBytes int) (*memhttp.Server, *encodingCapture, *sdk.ConnectRPCConnection, *connect.Client[wrapperspb.StringValue, wrapperspb.StringValue]) {
	tb.Helper()

	capture := &encodingCapture{handler: handler}
	memoryServer := memhttp.New(capture)
	ipcServer := inProcessServer{
		srv:                memoryServer,
		logger:             logger.CreateTestLogger(),
		maxCallRecvMsgSize: readMaxBytes,
		maxCallSendMsgSize: sendMaxBytes,
		disableCompression: disableCompression,
	}
	connection := ipcServer.Conn()
	client := connect.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](
		connection.Client,
		connection.Endpoint+ipcCompressionTestProcedure,
		connection.Options...,
	)
	return memoryServer, capture, connection, client
}

func TestIPCCompressionNegotiation(t *testing.T) {
	tests := []struct {
		name                        string
		disableCompression          bool
		wantAcceptEncoding          string
		wantResponseContentEncoding string
		wantTransportDisabled       bool
	}{
		{
			name:                        "default preserves gzip response negotiation",
			wantAcceptEncoding:          "gzip",
			wantResponseContentEncoding: "gzip",
		},
		{
			name:                  "opt-in uses identity response encoding",
			disableCompression:    true,
			wantTransportDisabled: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			memoryServer, capture, connection, client := newIPCCompressionTestClient(t, test.disableCompression, echoHandler())
			t.Cleanup(func() { require.NoError(t, memoryServer.Close()) })

			response, err := client.CallUnary(t.Context(), connect.NewRequest(&wrapperspb.StringValue{Value: strings.Repeat("compressible", 1024)}))
			require.NoError(t, err)
			require.Equal(t, strings.Repeat("compressible", 1024), response.Msg.GetValue())

			acceptEncoding, contentEncoding, responseEncoding := capture.encodings()
			assert.Equal(t, test.wantAcceptEncoding, acceptEncoding)
			assert.Empty(t, contentEncoding, "Connect requests remain identity-encoded")
			assert.Equal(t, test.wantResponseContentEncoding, responseEncoding)

			transport, ok := connection.Client.Transport.(*http2.Transport)
			require.True(t, ok)
			assert.Equal(t, test.wantTransportDisabled, transport.DisableCompression)
		})
	}
}

func TestNewOpenTDFServerIPCCompressionConfig(t *testing.T) {
	for _, disableCompression := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "opt-in"}[disableCompression], func(t *testing.T) {
			platformServer, err := NewOpenTDFServer(Config{
				Auth: auth.Config{Enabled: false},
				IPC:  IPCConfig{DisableCompression: disableCompression},
			}, logger.CreateTestLogger(), nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, platformServer.ConnectRPCInProcess.srv.Close()) })

			connection := platformServer.ConnectRPCInProcess.Conn()
			transport, ok := connection.Client.Transport.(*http2.Transport)
			require.True(t, ok)
			assert.Equal(t, disableCompression, transport.DisableCompression)
		})
	}
}

func TestIPCCompressionParity(t *testing.T) {
	t.Run("payload and error details", func(t *testing.T) {
		payloads := []string{"small", strings.Repeat("medium", 1024), strings.Repeat("large", 32*1024)}
		for _, payload := range payloads {
			var results [2]string
			for index, disableCompression := range []bool{false, true} {
				memoryServer, _, _, client := newIPCCompressionTestClient(t, disableCompression, echoHandler())
				response, err := client.CallUnary(t.Context(), connect.NewRequest(&wrapperspb.StringValue{Value: payload}))
				require.NoError(t, err)
				results[index] = response.Msg.GetValue()
				require.NoError(t, memoryServer.Close())
			}
			assert.Equal(t, results[0], results[1])
		}

		var errorsByMode [2]*connect.Error
		for index, disableCompression := range []bool{false, true} {
			memoryServer, _, _, client := newIPCCompressionTestClient(t, disableCompression, echoHandler())
			_, err := client.CallUnary(t.Context(), connect.NewRequest(&wrapperspb.StringValue{Value: "error"}))
			require.ErrorAs(t, err, &errorsByMode[index])
			require.NoError(t, memoryServer.Close())
		}
		assert.Equal(t, connect.CodeInvalidArgument, errorsByMode[0].Code())
		assert.Equal(t, errorsByMode[0].Code(), errorsByMode[1].Code())
		assert.Equal(t, errorsByMode[0].Message(), errorsByMode[1].Message())
		require.Len(t, errorsByMode[0].Details(), 1)
		require.Len(t, errorsByMode[1].Details(), 1)
		assert.Equal(t, errorsByMode[0].Details()[0].Type(), errorsByMode[1].Details()[0].Type())
		assert.Equal(t, errorsByMode[0].Details()[0].Bytes(), errorsByMode[1].Details()[0].Bytes())
	})

	t.Run("IPC metadata and server interceptor", func(t *testing.T) {
		for _, disableCompression := range []bool{false, true} {
			disableCompression := disableCompression
			t.Run(map[bool]string{false: "default", true: "compression-off"}[disableCompression], func(t *testing.T) {
				var interceptorCalls atomic.Int64
				var observedClientID, observedAccessToken string
				observationInterceptor := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
					return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
						interceptorCalls.Add(1)
						observedClientID = request.Header().Get("X-Ipc-Auth-Client-Id")
						observedAccessToken = request.Header().Get("X-Ipc-Access-Token")
						return next(ctx, request)
					}
				})
				memoryServer, _, _, client := newIPCCompressionTestClient(t, disableCompression, echoHandler(connect.WithInterceptors(observationInterceptor)))
				t.Cleanup(func() { require.NoError(t, memoryServer.Close()) })

				ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(ctxAuth.ClientIDKey, "parity-client"))
				ctx = ctxAuth.ContextWithAuthNInfo(ctx, nil, jwt.New(), "parity-access-token")
				response, err := client.CallUnary(ctx, connect.NewRequest(&wrapperspb.StringValue{Value: "metadata"}))
				require.NoError(t, err)
				assert.Equal(t, "metadata", response.Msg.GetValue())
				assert.Equal(t, int64(1), interceptorCalls.Load())
				assert.Equal(t, "parity-client", observedClientID)
				assert.Equal(t, "parity-access-token", observedAccessToken)
			})
		}
	})

	t.Run("client read and send limits", func(t *testing.T) {
		for _, disableCompression := range []bool{false, true} {
			disableCompression := disableCompression
			t.Run(map[bool]string{false: "default", true: "compression-off"}[disableCompression], func(t *testing.T) {
				memoryServer, _, _, client := newIPCCompressionTestClientWithLimits(t, disableCompression, echoHandler(), 64, 64)
				t.Cleanup(func() { require.NoError(t, memoryServer.Close()) })

				_, err := client.CallUnary(t.Context(), connect.NewRequest(&wrapperspb.StringValue{Value: strings.Repeat("request", 128)}))
				require.Error(t, err)
				assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))

				_, err = client.CallUnary(t.Context(), connect.NewRequest(&wrapperspb.StringValue{Value: "large-response"}))
				require.Error(t, err)
				assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
			})
		}
	})

	t.Run("in-flight cancellation reaches handler", func(t *testing.T) {
		for _, disableCompression := range []bool{false, true} {
			disableCompression := disableCompression
			t.Run(map[bool]string{false: "default", true: "compression-off"}[disableCompression], func(t *testing.T) {
				handlerStarted := make(chan struct{})
				handlerCanceled := make(chan struct{})
				handler := connect.NewUnaryHandler(
					ipcCompressionTestProcedure,
					func(ctx context.Context, _ *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
						close(handlerStarted)
						<-ctx.Done()
						close(handlerCanceled)
						return nil, connect.NewError(connect.CodeCanceled, ctx.Err())
					},
				)
				memoryServer, _, _, client := newIPCCompressionTestClient(t, disableCompression, handler)
				t.Cleanup(func() { require.NoError(t, memoryServer.Close()) })

				ctx, cancel := context.WithCancel(t.Context())
				callDone := make(chan error, 1)
				go func() {
					_, err := client.CallUnary(ctx, connect.NewRequest(&wrapperspb.StringValue{Value: "wait"}))
					callDone <- err
				}()
				requireSignal(t, handlerStarted, "handler start")
				cancel()
				requireSignal(t, handlerCanceled, "handler cancellation")
				select {
				case err := <-callDone:
					require.Error(t, err)
					assert.Equal(t, connect.CodeCanceled, connect.CodeOf(err))
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for canceled IPC call")
				}
			})
		}
	})
}

func requireSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestIPCCompressionSampledLatencies(t *testing.T) {
	if os.Getenv("OPENTDF_IPC_COMPRESSION_SAMPLE") == "" {
		t.Skip("set OPENTDF_IPC_COMPRESSION_SAMPLE=1 to collect sampled latency percentiles")
	}

	iterations := 100
	if configured := os.Getenv("OPENTDF_IPC_COMPRESSION_SAMPLE_ITERATIONS"); configured != "" {
		parsed, err := strconv.Atoi(configured)
		require.NoError(t, err)
		require.Positive(t, parsed)
		iterations = parsed
	}

	for _, payload := range []struct {
		name  string
		value string
	}{
		{name: "small", value: strings.Repeat("s", 64)},
		{name: "medium", value: strings.Repeat("m", 8*1024)},
		{name: "large", value: strings.Repeat("l", 256*1024)},
	} {
		for _, sample := range []struct {
			name               string
			disableCompression bool
			loopback           bool
		}{
			{name: "ipc-default"},
			{name: "ipc-compression-off", disableCompression: true},
			{name: "loopback-default", loopback: true},
		} {
			t.Run(payload.name+"/"+sample.name, func(t *testing.T) {
				client, _, cleanup := newCompressionHarnessClient(t, sample.disableCompression, sample.loopback)
				t.Cleanup(cleanup)
				latencies := make([]time.Duration, 0, iterations)
				for range iterations {
					started := time.Now()
					response, err := client.CallUnary(t.Context(), connect.NewRequest(&wrapperspb.StringValue{Value: payload.value}))
					latencies = append(latencies, time.Since(started))
					require.NoError(t, err)
					require.Equal(t, payload.value, response.Msg.GetValue())
				}
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				t.Logf("measured samples=%d payload_bytes=%d goos=%s goarch=%s gomaxprocs=%d p50=%s p95=%s p99=%s",
					len(latencies), len(payload.value), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0),
					sampledPercentile(latencies, 50), sampledPercentile(latencies, 95), sampledPercentile(latencies, 99))
			})
		}
	}
}

func sampledPercentile(sortedSamples []time.Duration, percentile int) time.Duration {
	index := (len(sortedSamples)*percentile + 99) / 100
	if index > 0 {
		index--
	}
	return sortedSamples[index]
}

func newCompressionHarnessClient(tb testing.TB, disableCompression, loopback bool) (*connect.Client[wrapperspb.StringValue, wrapperspb.StringValue], *encodingCapture, func()) {
	tb.Helper()
	if loopback {
		capture := &encodingCapture{handler: echoHandler()}
		server := httptest.NewServer(capture)
		return connect.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](server.Client(), server.URL+ipcCompressionTestProcedure), capture, server.Close
	}
	memoryServer, capture, _, client := newIPCCompressionTestClient(tb, disableCompression, echoHandler())
	return client, capture, func() {
		if err := memoryServer.Close(); err != nil {
			tb.Errorf("close memory server: %v", err)
		}
	}
}

func BenchmarkIPCCompression(b *testing.B) {
	payloads := []struct {
		name  string
		value string
	}{
		{name: "small", value: strings.Repeat("s", 64)},
		{name: "medium", value: strings.Repeat("m", 8*1024)},
		{name: "large", value: strings.Repeat("l", 256*1024)},
	}
	for _, payload := range payloads {
		for _, benchmark := range []struct {
			name               string
			disableCompression bool
			loopback           bool
		}{
			{name: "ipc-default"},
			{name: "ipc-compression-off", disableCompression: true},
			{name: "loopback-default", loopback: true},
		} {
			for _, parallel := range []bool{false, true} {
				concurrency := map[bool]string{false: "serial", true: "parallel"}[parallel]
				b.Run(payload.name+"/"+benchmark.name+"/"+concurrency, func(b *testing.B) {
					client, capture, cleanup := newCompressionHarnessClient(b, benchmark.disableCompression, benchmark.loopback)
					b.Cleanup(cleanup)
					call := func() {
						response, err := client.CallUnary(context.Background(), connect.NewRequest(&wrapperspb.StringValue{Value: payload.value}))
						if err != nil || response.Msg.GetValue() != payload.value {
							b.Fatalf("echo mismatch: response=%v error=%v", response, err)
						}
					}

					b.ReportAllocs()
					b.SetBytes(int64(len(payload.value)))
					b.ResetTimer()
					if parallel {
						b.RunParallel(func(pb *testing.PB) {
							for pb.Next() {
								call()
							}
						})
					} else {
						for range b.N {
							call()
						}
					}
					b.StopTimer()
					b.ReportMetric(float64(capture.responseBodyBytes.Load())/float64(b.N), "response-body-B/op")
				})
			}
		}
	}
}
