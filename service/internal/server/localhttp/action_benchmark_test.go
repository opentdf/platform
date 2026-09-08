package localhttp

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
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type actionFixture struct {
	actionsconnect.UnimplementedActionServiceHandler
	payload   string
	mutations *atomic.Int64
}

func (f actionFixture) GetAction(_ context.Context, req *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	if f.mutations != nil {
		f.mutations.Add(1)
	}
	return fixtureResponse(&actions.GetActionResponse{Action: &policy.Action{Id: req.Msg.GetId(), Name: f.payload}}), nil
}

func (f actionFixture) ListActions(context.Context, *connect.Request[actions.ListActionsRequest]) (*connect.Response[actions.ListActionsResponse], error) {
	return fixtureResponse(&actions.ListActionsResponse{ActionsCustom: []*policy.Action{{Id: "listed", Name: f.payload}}}), nil
}

func (f actionFixture) CreateAction(_ context.Context, req *connect.Request[actions.CreateActionRequest]) (*connect.Response[actions.CreateActionResponse], error) {
	if f.mutations != nil {
		f.mutations.Add(1)
	}
	return fixtureResponse(&actions.CreateActionResponse{Action: &policy.Action{Id: "created", Name: req.Msg.GetName()}}), nil
}

func (f actionFixture) UpdateAction(_ context.Context, req *connect.Request[actions.UpdateActionRequest]) (*connect.Response[actions.UpdateActionResponse], error) {
	return fixtureResponse(&actions.UpdateActionResponse{Action: &policy.Action{Id: req.Msg.GetId(), Name: req.Msg.GetName()}}), nil
}

func (f actionFixture) DeleteAction(_ context.Context, req *connect.Request[actions.DeleteActionRequest]) (*connect.Response[actions.DeleteActionResponse], error) {
	return fixtureResponse(&actions.DeleteActionResponse{Action: &policy.Action{Id: req.Msg.GetId(), Name: f.payload}}), nil
}

func fixtureResponse[T any](message *T) *connect.Response[T] {
	resp := connect.NewResponse(message)
	resp.Header().Set("X-Action-Fixture", "true")
	resp.Trailer().Set("X-Action-Trailer", "done")
	return resp
}

func TestActionClientParityThroughMux(t *testing.T) {
	path, handler := actionsconnect.NewActionServiceHandler(actionFixture{payload: "read"})
	mux := http.NewServeMux()
	mux.Handle(path, handler)

	v1 := memhttp.New(mux)
	t.Cleanup(func() { require.NoError(t, v1.Cleanup()) })
	candidateTransport := &Transport{Handler: mux}

	clients := map[string]actionsconnect.ActionServiceClient{
		"v1":        actionsconnect.NewActionServiceClient(v1.Client(), v1.Listener.Addr().String()),
		"candidate": actionsconnect.NewActionServiceClient(candidateTransport.Client(), "http://local.test"),
	}
	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			req := connect.NewRequest(actionRequest("action-id"))
			req.Header().Set("X-Ipc-Test", "serialized")
			resp, err := client.GetAction(t.Context(), req)
			require.NoError(t, err)
			assert.Equal(t, "action-id", resp.Msg.GetAction().GetId())
			assert.Equal(t, "read", resp.Msg.GetAction().GetName())
			assert.Equal(t, "true", resp.Header().Get("X-Action-Fixture"))
			assert.Equal(t, "done", resp.Trailer().Get("X-Action-Trailer"))

			listed, err := client.ListActions(t.Context(), connect.NewRequest(&actions.ListActionsRequest{}))
			require.NoError(t, err)
			assert.Equal(t, "listed", listed.Msg.GetActionsCustom()[0].GetId())
			created, err := client.CreateAction(t.Context(), connect.NewRequest(&actions.CreateActionRequest{Name: "created-name"}))
			require.NoError(t, err)
			assert.Equal(t, "created-name", created.Msg.GetAction().GetName())
			updated, err := client.UpdateAction(t.Context(), connect.NewRequest(&actions.UpdateActionRequest{Id: "updated", Name: "updated-name"}))
			require.NoError(t, err)
			assert.Equal(t, "updated", updated.Msg.GetAction().GetId())
			deleted, err := client.DeleteAction(t.Context(), connect.NewRequest(&actions.DeleteActionRequest{Id: "deleted"}))
			require.NoError(t, err)
			assert.Equal(t, "deleted", deleted.Msg.GetAction().GetId())
		})
	}
}

func TestActionGeneratedClientErrorParity(t *testing.T) {
	t.Run("application error details and metadata", func(t *testing.T) {
		detail, err := connect.NewErrorDetail(actionRequest("detail-id"))
		require.NoError(t, err)
		applicationErr := connect.NewError(connect.CodePermissionDenied, errors.New("denied"))
		applicationErr.Meta().Set("X-Error-Metadata", "preserved")
		applicationErr.AddDetail(detail)
		path, handler := actionsconnect.NewActionServiceHandler(actionErrorFixture{err: applicationErr})
		mux := http.NewServeMux()
		mux.Handle(path, handler)

		observed := generatedClientErrors(t, mux)
		for name, got := range observed {
			require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(got), name)
			var connectErr *connect.Error
			require.ErrorAs(t, got, &connectErr, name)
			assert.Equal(t, "preserved", connectErr.Meta().Get("X-Error-Metadata"), name)
			require.Len(t, connectErr.Details(), 1, name)
			value, valueErr := connectErr.Details()[0].Value()
			require.NoError(t, valueErr, name)
			assert.True(t, proto.Equal(actionRequest("detail-id"), value), name)
		}
		assert.Equal(t, connect.CodeOf(observed["v1"]), connect.CodeOf(observed["candidate"]))
	})

	for name, encoded := range map[string][]byte{
		"malformed protobuf": {0x0f},
		"truncated protobuf": {0x0a, 0x05, 'x'},
	} {
		t.Run(name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/proto")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(encoded)
			})
			observed := generatedClientErrors(t, handler)
			for transport, got := range observed {
				require.Error(t, got, transport)
				var connectErr *connect.Error
				require.ErrorAs(t, got, &connectErr, transport)
			}
			assert.Equal(t, connect.CodeOf(observed["v1"]), connect.CodeOf(observed["candidate"]),
				"malformed response failure class must match without comparing transport-specific text")
		})
	}
}

func TestActionPanicCharacterizationAndNoReplay(t *testing.T) {
	for _, afterEncodedResponse := range []bool{false, true} {
		name := "before-commit"
		if afterEncodedResponse {
			name = "after-complete-encoded-response"
		}
		t.Run(name, func(t *testing.T) {
			calls := map[string]*atomic.Int64{"v1": {}, "candidate": {}}
			mutations := map[string]*atomic.Int64{"v1": {}, "candidate": {}}
			handlers := make(map[string]http.Handler, len(mutations))
			for transportName, mutation := range mutations {
				handlers[transportName] = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls[transportName].Add(1)
					if afterEncodedResponse {
						mutation.Add(1)
						encoded, err := proto.Marshal(&actions.GetActionResponse{Action: &policy.Action{Id: "one-mutation"}})
						if err != nil {
							panic(err)
						}
						w.Header().Set("Content-Type", "application/proto")
						w.WriteHeader(http.StatusOK)
						if _, err = w.Write(encoded); err != nil {
							panic(err)
						}
					}
					panic("characterized panic")
				})
			}
			observed := generatedClientErrorsByTransport(t, handlers)
			for transportName, err := range observed {
				require.Error(t, err, "panic must not produce a successful generated-client result")
				var connectErr *connect.Error
				require.ErrorAs(t, err, &connectErr, transportName)
				require.Equal(t, connect.CodeInternal, connectErr.Code(), transportName)
				wantMutations := int64(0)
				if afterEncodedResponse {
					wantMutations = 1
				}
				require.Eventually(t, func() bool { return calls[transportName].Load() == 1 }, time.Second, time.Millisecond,
					"transport dispatches exactly once and never replays")
				assert.Equal(t, wantMutations, mutations[transportName].Load(), transportName)
			}
			assert.Equal(t, connect.CodeOf(observed["v1"]), connect.CodeOf(observed["candidate"]))
		})
	}
}

type actionErrorFixture struct {
	actionsconnect.UnimplementedActionServiceHandler
	err error
}

func (f actionErrorFixture) GetAction(context.Context, *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	return nil, f.err
}

func generatedClientErrors(t *testing.T, handler http.Handler) map[string]error {
	t.Helper()
	return generatedClientErrorsByTransport(t, map[string]http.Handler{"v1": handler, "candidate": handler})
}

func generatedClientErrorsByTransport(t *testing.T, handlers map[string]http.Handler) map[string]error {
	t.Helper()
	observed := make(map[string]error, len(handlers))
	for name, handler := range handlers {
		var client actionsconnect.ActionServiceClient
		if name == "v1" {
			v1 := memhttp.New(handler)
			t.Cleanup(func() { _ = v1.Cleanup() })
			client = actionsconnect.NewActionServiceClient(v1.Client(), v1.Listener.Addr().String())
		} else {
			client = actionsconnect.NewActionServiceClient((&Transport{Handler: handler}).Client(), "http://local.test")
		}
		_, observed[name] = client.GetAction(t.Context(), connect.NewRequest(actionRequest("one-mutation")))
	}
	return observed
}

func TestActionProtobufRequestAndResponseIsolation(t *testing.T) {
	returned := make(chan *policy.Action, 1)
	fixture := actionIsolationFixture{returned: returned}
	path, handler := actionsconnect.NewActionServiceHandler(fixture)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	client := actionsconnect.NewActionServiceClient((&Transport{Handler: mux}).Client(), "http://local.test")

	requestMessage := &actions.CreateActionRequest{Name: "caller-owned"}
	response, err := client.CreateAction(t.Context(), connect.NewRequest(requestMessage))
	require.NoError(t, err)
	assert.Equal(t, "caller-owned", requestMessage.GetName())
	serverResponse := <-returned
	serverResponse.Name = "server-mutated-after-encoding"
	assert.Equal(t, "encoded-response", response.Msg.GetAction().GetName())
}

type actionIsolationFixture struct {
	actionsconnect.UnimplementedActionServiceHandler
	returned chan<- *policy.Action
}

func (f actionIsolationFixture) CreateAction(_ context.Context, req *connect.Request[actions.CreateActionRequest]) (*connect.Response[actions.CreateActionResponse], error) {
	req.Msg.Name = "server-decoded-copy"
	action := &policy.Action{Id: "isolated", Name: "encoded-response"}
	f.returned <- action
	return connect.NewResponse(&actions.CreateActionResponse{Action: action}), nil
}

type compressionWireObservation struct {
	acceptEncoding          string
	connectAcceptEncoding   string
	requestEncoding         string
	connectRequestEncoding  string
	responseEncoding        string
	connectResponseEncoding string
}

type compressionObservingHandler struct {
	next         http.Handler
	observations chan<- compressionWireObservation
}

func (h compressionObservingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.next.ServeHTTP(w, req)
	h.observations <- compressionWireObservation{
		acceptEncoding:          req.Header.Get("Accept-Encoding"),
		connectAcceptEncoding:   req.Header.Get("Connect-Accept-Encoding"),
		requestEncoding:         req.Header.Get("Content-Encoding"),
		connectRequestEncoding:  req.Header.Get("Connect-Content-Encoding"),
		responseEncoding:        w.Header().Get("Content-Encoding"),
		connectResponseEncoding: w.Header().Get("Connect-Content-Encoding"),
	}
}

func TestActionCompressionNegotiationOnWire(t *testing.T) {
	_, actionHandler := actionsconnect.NewActionServiceHandler(actionFixture{payload: strings.Repeat("x", 1024)})
	observations := make(chan compressionWireObservation, 3)
	handler := compressionObservingHandler{next: actionHandler, observations: observations}
	v1 := memhttp.New(handler)
	t.Cleanup(func() { require.NoError(t, v1.Cleanup()) })
	candidate := &Transport{Handler: handler}
	t.Cleanup(func() { require.NoError(t, candidate.Shutdown(context.Background())) })

	v1CompressionOff := v1.Transport()
	v1CompressionOff.DisableCompression = true
	compressionOff := connect.WithAcceptCompression("gzip", nil, nil)
	clients := map[string]struct {
		client                  actionsconnect.ActionServiceClient
		wantResponseCompression bool
	}{
		"v1-default": {
			client:                  actionsconnect.NewActionServiceClient(v1.Client(), v1.Listener.Addr().String()),
			wantResponseCompression: true,
		},
		"v1-compression-off": {
			client: actionsconnect.NewActionServiceClient(
				&http.Client{Transport: v1CompressionOff}, v1.Listener.Addr().String(), compressionOff,
			),
		},
		"v2-fixed-identity": {
			client: actionsconnect.NewActionServiceClient(candidate.Client(), "http://local.test"),
		},
	}
	for name, tc := range clients {
		t.Run(name, func(t *testing.T) {
			resp, err := tc.client.GetAction(t.Context(), connect.NewRequest(actionRequest("compression-wire")))
			require.NoError(t, err)
			require.Len(t, resp.Msg.GetAction().GetName(), 1024)

			observed := <-observations
			assert.Empty(t, observed.requestEncoding, "requests remain identity encoded")
			assert.Empty(t, observed.connectRequestEncoding, "requests remain identity encoded")
			if tc.wantResponseCompression {
				assert.Contains(t, observed.acceptEncoding, "gzip", "server observes default response negotiation")
				assert.Equal(t, "gzip", observed.responseEncoding, "server writes a gzip-encoded response")
			} else {
				assert.NotContains(t, observed.acceptEncoding, "gzip", "server observes compression disabled")
				assert.Empty(t, observed.responseEncoding, "server writes an identity response")
			}
			assert.Empty(t, observed.connectAcceptEncoding)
			assert.Empty(t, observed.connectResponseEncoding)
		})
	}
}

type benchmarkFixture struct {
	client  actionsconnect.ActionServiceClient
	cleanup func()
}

func newBenchmarkFixtures(b testing.TB, payloadSize int, syntheticWrapper bool) map[string]benchmarkFixture {
	b.Helper()
	_, actionHandler := actionsconnect.NewActionServiceHandler(actionFixture{payload: strings.Repeat("x", payloadSize)})
	handler := benchmarkHandler(actionHandler, syntheticWrapper)

	v1 := memhttp.New(handler)
	candidate := &Transport{Handler: handler}
	remote := httptest.NewServer(handler)
	v1CompressionOff := v1.Transport()
	v1CompressionOff.DisableCompression = true
	compressionOff := connect.WithAcceptCompression("gzip", nil, nil)
	return map[string]benchmarkFixture{
		"v1-default": {
			client:  actionsconnect.NewActionServiceClient(v1.Client(), v1.Listener.Addr().String()),
			cleanup: func() { _ = v1.Cleanup() },
		},
		"v1-compression-off": {
			client: actionsconnect.NewActionServiceClient(
				&http.Client{Transport: v1CompressionOff}, v1.Listener.Addr().String(), compressionOff,
			),
			cleanup: func() {},
		},
		"v2-fixed-identity": {
			client:  actionsconnect.NewActionServiceClient(candidate.Client(), "http://local.test"),
			cleanup: func() {},
		},
		"remote-loopback": {
			client:  actionsconnect.NewActionServiceClient(remote.Client(), remote.URL),
			cleanup: remote.Close,
		},
	}
}

func benchmarkHandler(actionHandler http.Handler, syntheticWrapper bool) http.Handler {
	if !syntheticWrapper {
		return actionHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Synthetic-Wrapper", "true")
		actionHandler.ServeHTTP(w, req)
	})
}

func BenchmarkActionTransports(b *testing.B) {
	payloadSize := envInt("IPC_BENCH_PAYLOAD_BYTES", 1024)
	for _, syntheticWrapper := range []bool{false, true} {
		caseName := "raw"
		if syntheticWrapper {
			caseName = "synthetic-wrapper"
		}
		fixtures := newBenchmarkFixtures(b, payloadSize, syntheticWrapper)
		for name, fixture := range fixtures {
			b.Run(caseName+"/"+name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(payloadSize))
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						resp, err := fixture.client.GetAction(b.Context(), connect.NewRequest(actionRequest("benchmark")))
						if err != nil || resp.Msg.GetAction().GetName() == "" {
							b.Fatalf("Action GetAction failed: %v", err)
						}
					}
				})
			})
		}
		for _, fixture := range fixtures {
			fixture.cleanup()
		}
	}
}

func TestActionSyntheticWrapperSampledLatency(t *testing.T) {
	if os.Getenv("IPC_V2_SAMPLE_LATENCY") == "" {
		t.Skip("set IPC_V2_SAMPLE_LATENCY=1 to collect actual sampled percentiles")
	}
	samples := envInt("IPC_BENCH_SAMPLES", 1000)
	payloadSize := envInt("IPC_BENCH_PAYLOAD_BYTES", 1024)
	fixtures := newBenchmarkFixtures(t, payloadSize, true)
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			latencies := make([]time.Duration, samples)
			for i := range samples {
				start := time.Now()
				_, err := fixture.client.GetAction(t.Context(), connect.NewRequest(actionRequest("sample")))
				require.NoError(t, err)
				latencies[i] = time.Since(start)
			}
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			t.Logf("transport=%s samples=%d payload_bytes=%d goos=%s goarch=%s go_version=%s gomaxprocs=%d p50=%s p95=%s p99=%s",
				name, samples, payloadSize, runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.GOMAXPROCS(0),
				percentile(latencies, 50), percentile(latencies, 95), percentile(latencies, 99))
		})
	}
	for _, fixture := range fixtures {
		fixture.cleanup()
	}
}

func actionRequest(id string) *actions.GetActionRequest {
	return &actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: id}}
}

func percentile(samples []time.Duration, percentile int) time.Duration {
	index := (len(samples)*percentile + 99) / 100
	if index < 1 {
		index = 1
	}
	return samples[index-1]
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		panic(name + " must be a positive integer")
	}
	return parsed
}
