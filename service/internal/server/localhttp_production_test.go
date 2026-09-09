package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/auth"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/internal/server/localhttp"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
)

const (
	productionTestSendLimit        = 512
	productionTestReadLimit        = 2048
	productionBenchmarkPayloadSize = 1024
)

type productionObservation struct {
	principal   string
	auditActor  string
	clientID    string
	traceID     trace.TraceID
	callerValue any
	incoming    metadata.MD
}

type productionActionFixture struct {
	actionsconnect.UnimplementedActionServiceHandler
	observed          chan<- productionObservation
	responseName      string
	nestedClient      actionsconnect.ActionServiceClient
	nestedCallerToken string
	nestedHeaderToken string
	nestedExpected    chan trace.TraceID
}

func (f *productionActionFixture) GetAction(ctx context.Context, req *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	f.observe(ctx)
	name := f.responseName
	if name == "" {
		name = "production-stack"
	}
	if req.Msg.GetId() == "00000000-0000-0000-0000-000000000006" {
		name = strings.Repeat("x", productionTestReadLimit*2)
	}
	if req.Msg.GetId() == "00000000-0000-0000-0000-000000000031" && f.nestedClient != nil {
		nestedCtx := context.WithValue(ctx, productionContextKey{}, "nested-caller-only")
		nestedCtx = metadata.NewIncomingContext(nestedCtx, metadata.Pairs(ctxAuth.ClientIDKey, "nested-caller-client", "nested-caller-only", "must-not-cross"))
		callerJWT, err := jwt.Parse([]byte(f.nestedCallerToken), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			return nil, err
		}
		nestedCtx = ctxAuth.ContextWithAuthNInfo(nestedCtx, nil, callerJWT, f.nestedCallerToken)
		nestedCtx = audit.ContextWithActorID(nestedCtx, "nested-caller-audit")
		nestedCtx, span := otel.Tracer("localhttp-nested-production-test").Start(nestedCtx, "nested-caller")
		defer span.End()
		f.nestedExpected <- span.SpanContext().TraceID()

		nestedReq := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000032"}})
		nestedReq.Header().Set("X-Ipc-Access-Token", f.nestedHeaderToken)
		nestedReq.Header().Set("X-Ipc-Auth-Client-Id", "nested-header-client")
		if _, err = f.nestedClient.GetAction(nestedCtx, nestedReq); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&actions.GetActionResponse{Action: &policy.Action{Id: req.Msg.GetId(), Name: name}}), nil
}

func (f productionActionFixture) ListActions(ctx context.Context, _ *connect.Request[actions.ListActionsRequest]) (*connect.Response[actions.ListActionsResponse], error) {
	f.observe(ctx)
	return connect.NewResponse(&actions.ListActionsResponse{ActionsCustom: []*policy.Action{{Id: "00000000-0000-0000-0000-000000000011", Name: "listed"}}}), nil
}

func (f productionActionFixture) CreateAction(ctx context.Context, req *connect.Request[actions.CreateActionRequest]) (*connect.Response[actions.CreateActionResponse], error) {
	f.observe(ctx)
	return connect.NewResponse(&actions.CreateActionResponse{Action: &policy.Action{Id: "00000000-0000-0000-0000-000000000012", Name: req.Msg.GetName()}}), nil
}

func (f productionActionFixture) UpdateAction(ctx context.Context, req *connect.Request[actions.UpdateActionRequest]) (*connect.Response[actions.UpdateActionResponse], error) {
	f.observe(ctx)
	return connect.NewResponse(&actions.UpdateActionResponse{Action: &policy.Action{Id: req.Msg.GetId(), Name: req.Msg.GetName()}}), nil
}

func (f productionActionFixture) DeleteAction(ctx context.Context, req *connect.Request[actions.DeleteActionRequest]) (*connect.Response[actions.DeleteActionResponse], error) {
	f.observe(ctx)
	return connect.NewResponse(&actions.DeleteActionResponse{Action: &policy.Action{Id: req.Msg.GetId()}}), nil
}

func (f productionActionFixture) observe(ctx context.Context) {
	principal, _ := ctxAuth.PrincipalFromContext(ctx)
	clientID, _ := ctxAuth.GetClientIDFromContext(ctx, true)
	incoming, _ := metadata.FromIncomingContext(ctx)
	f.observed <- productionObservation{
		principal: principal.Subject, auditActor: audit.GetAuditDataFromContext(ctx).ActorID, clientID: clientID,
		traceID: trace.SpanContextFromContext(ctx).TraceID(), callerValue: ctx.Value(productionContextKey{}), incoming: incoming,
	}
}

type productionContextKey struct{}

type productionEntryObservation struct {
	headers        http.Header
	callerValue    any
	rawToken       string
	hasIncoming    bool
	auditActor     string
	spanContextSet bool
}

type productionHarness struct {
	handler      http.Handler
	v1           *memhttp.Server
	candidate    *localhttp.Transport
	clientOpts   []connect.ClientOption
	fixture      *productionActionFixture
	observations <-chan productionObservation
	entries      <-chan productionEntryObservation
}

func newProductionHarness(t testing.TB) *productionHarness {
	t.Helper()
	log := logger.CreateTestLogger()
	authenticator := newProductionTestAuthenticator(t, log)
	cfg := Config{Auth: auth.Config{Enabled: true}}
	rpc, err := newConnectRPC(cfg, []connect.Interceptor{authenticator.IPCUnaryServerInterceptor()}, nil, log)
	require.NoError(t, err)

	observations := make(chan productionObservation, 32)
	entries := make(chan productionEntryObservation, 32)
	fixture := &productionActionFixture{observed: observations, nestedExpected: make(chan trace.TraceID, 2)}
	path, actionHandler := actionsconnect.NewActionServiceHandler(fixture, rpc.Interceptors...)
	rpc.Mux.Handle(path, actionHandler)

	entryHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, hasIncoming := metadata.FromIncomingContext(req.Context())
		entries <- productionEntryObservation{
			headers:        req.Header.Clone(),
			callerValue:    req.Context().Value(productionContextKey{}),
			rawToken:       ctxAuth.GetRawAccessTokenFromContext(req.Context(), log),
			hasIncoming:    hasIncoming,
			auditActor:     audit.GetAuditDataFromContext(req.Context()).ActorID,
			spanContextSet: trace.SpanContextFromContext(req.Context()).IsValid(),
		}
		rpc.Mux.ServeHTTP(w, req)
	})

	clientTrace, err := tracing.ConnectClientTraceInterceptor()
	require.NoError(t, err)
	clientOpts := []connect.ClientOption{
		connect.WithInterceptors(clientTrace, sdkAudit.MetadataAddingConnectInterceptor(), auth.IPCMetadataClientInterceptor(log)),
		connect.WithReadMaxBytes(productionTestReadLimit),
		connect.WithSendMaxBytes(productionTestSendLimit),
	}
	v1 := memhttp.New(entryHandler)
	candidate := &localhttp.Transport{Handler: entryHandler}
	t.Cleanup(func() {
		require.NoError(t, candidate.Shutdown(context.Background()))
		require.NoError(t, v1.Cleanup())
	})
	return &productionHarness{
		handler: entryHandler, v1: v1, candidate: candidate, clientOpts: clientOpts,
		fixture: fixture, observations: observations, entries: entries,
	}
}

func (h *productionHarness) clients() map[string]actionsconnect.ActionServiceClient {
	compressionOff := connect.WithAcceptCompression("gzip", nil, nil)
	offOpts := append(append([]connect.ClientOption{}, h.clientOpts...), compressionOff)
	v1CompressionOff := h.v1.Transport()
	v1CompressionOff.DisableCompression = true
	return map[string]actionsconnect.ActionServiceClient{
		"v1-default": actionsconnect.NewActionServiceClient(
			h.v1.Client(), h.v1.Listener.Addr().String(), h.clientOpts...,
		),
		"v1-compression-off": actionsconnect.NewActionServiceClient(
			&http.Client{Transport: v1CompressionOff}, h.v1.Listener.Addr().String(), offOpts...,
		),
		"v2-fixed-identity": actionsconnect.NewActionServiceClient(
			h.candidate.Client(), "http://local.test", h.clientOpts...,
		),
	}
}

func newProductionTestAuthenticator(t testing.TB, log *logger.Logger) *auth.Authentication {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicJWK, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, publicJWK.Set(jws.KeyIDKey, "local-production-test"))
	require.NoError(t, publicJWK.Set(jwk.AlgorithmKey, jwa.RS256))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(publicJWK))

	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(set)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(issuer.Close)

	policy := internalauthz.PolicyConfig{ClientIDClaim: "cid"}
	require.NoError(t, defaults.Set(&policy))
	result, err := auth.NewAuthenticator(context.Background(), auth.Config{AuthNConfig: auth.AuthNConfig{
		Issuer: issuer.URL, Audience: "local-production-test", Policy: policy, CacheRefresh: "15m", DPoPSkew: time.Hour, TokenSkew: time.Minute,
	}}, log, func(string, any) error { return nil })
	require.NoError(t, err)
	return result
}

func unsignedProductionToken(t testing.TB, subject string) string {
	t.Helper()
	token, err := jwt.NewBuilder().Subject(subject).Build()
	require.NoError(t, err)
	raw, err := jwt.Sign(token, jwt.WithInsecureNoSignature())
	require.NoError(t, err)
	return string(raw)
}

func setupProductionTracing(t *testing.T) *sdktrace.TracerProvider {
	t.Helper()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(tracetest.NewInMemoryExporter()), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})
	return tp
}

func TestLocalHTTPProductionIPCStackParity(t *testing.T) {
	tp := setupProductionTracing(t)
	harness := newProductionHarness(t)
	headerToken := unsignedProductionToken(t, "header-principal")
	callerToken := unsignedProductionToken(t, "caller-principal")

	for name, client := range harness.clients() {
		t.Run(name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), productionContextKey{}, "must-not-cross-server-entry")
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(ctxAuth.ClientIDKey, "caller-client", "caller-only", "must-not-cross"))
			callerJWT, err := jwt.Parse([]byte(callerToken), jwt.WithVerify(false), jwt.WithValidate(false))
			require.NoError(t, err)
			ctx = ctxAuth.ContextWithAuthNInfo(ctx, nil, callerJWT, callerToken)
			ctx = audit.ContextWithActorID(ctx, "caller-audit")
			ctx, span := tp.Tracer("localhttp-production-test").Start(ctx, "caller")
			defer span.End()

			req := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000001"}})
			req.Header().Set("X-Ipc-Access-Token", headerToken)
			req.Header().Set("X-Ipc-Auth-Client-Id", "header-client")
			resp, err := client.GetAction(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, "00000000-0000-0000-0000-000000000001", resp.Msg.GetAction().GetId())

			entry := <-harness.entries
			assertCleanProductionEntry(t, entry)
			observed := <-harness.observations
			assert.Equal(t, "header-principal", observed.principal)
			assert.Equal(t, "header-principal", observed.auditActor)
			assert.Equal(t, "header-client", observed.clientID)
			assert.Equal(t, span.SpanContext().TraceID(), observed.traceID)
			assert.Nil(t, observed.callerValue)
			assert.Empty(t, observed.incoming.Get("caller-only"))
		})
	}
}

func assertCleanProductionEntry(t *testing.T, entry productionEntryObservation) {
	t.Helper()
	assert.Nil(t, entry.callerValue)
	assert.Empty(t, entry.rawToken)
	assert.False(t, entry.hasIncoming)
	assert.Empty(t, entry.auditActor)
	assert.False(t, entry.spanContextSet)
}

func TestLocalHTTPProductionIPCStackNestedAuthorityBoundary(t *testing.T) {
	setupProductionTracing(t)
	harness := newProductionHarness(t)
	harness.fixture.nestedCallerToken = unsignedProductionToken(t, "nested-caller-principal")
	harness.fixture.nestedHeaderToken = unsignedProductionToken(t, "nested-header-principal")

	for name, client := range harness.clients() {
		t.Run(name, func(t *testing.T) {
			harness.fixture.nestedClient = client
			resp, err := client.GetAction(t.Context(), connect.NewRequest(&actions.GetActionRequest{
				Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000031"},
			}))
			require.NoError(t, err)
			assert.Equal(t, "00000000-0000-0000-0000-000000000031", resp.Msg.GetAction().GetId())

			expectedTraceID := <-harness.fixture.nestedExpected
			rootEntry := <-harness.entries
			nestedEntry := <-harness.entries
			assertCleanProductionEntry(t, rootEntry)
			assertCleanProductionEntry(t, nestedEntry)
			assert.Contains(t, nestedEntry.headers.Values("X-Ipc-Access-Token"), harness.fixture.nestedHeaderToken)
			assert.Contains(t, nestedEntry.headers.Values("X-Ipc-Access-Token"), harness.fixture.nestedCallerToken)
			assert.Contains(t, nestedEntry.headers.Values("X-Ipc-Auth-Client-Id"), "nested-header-client")
			assert.Contains(t, nestedEntry.headers.Values("X-Ipc-Auth-Client-Id"), "nested-caller-client")
			assert.NotEmpty(t, nestedEntry.headers.Get("Traceparent"))
			assert.Empty(t, nestedEntry.headers.Get("Nested-Caller-Only"))

			rootObserved := <-harness.observations
			nestedObserved := <-harness.observations
			assert.Empty(t, rootObserved.principal)
			assert.Equal(t, "nested-header-principal", nestedObserved.principal)
			assert.Equal(t, "nested-header-principal", nestedObserved.auditActor)
			assert.Equal(t, "nested-header-client", nestedObserved.clientID)
			assert.Equal(t, expectedTraceID, nestedObserved.traceID)
			assert.Nil(t, nestedObserved.callerValue)
			assert.Empty(t, nestedObserved.incoming.Get("nested-caller-only"))
		})
	}
}

func TestLocalHTTPProductionIPCStackAllActionMethods(t *testing.T) {
	setupProductionTracing(t)
	harness := newProductionHarness(t)
	for name, client := range harness.clients() {
		t.Run(name, func(t *testing.T) {
			get, err := client.GetAction(t.Context(), connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000021"}}))
			require.NoError(t, err)
			assert.NotNil(t, get.Msg.GetAction())
			<-harness.observations
			<-harness.entries
			list, err := client.ListActions(t.Context(), connect.NewRequest(&actions.ListActionsRequest{}))
			require.NoError(t, err)
			assert.NotEmpty(t, list.Msg.GetActionsCustom())
			<-harness.observations
			<-harness.entries
			created, err := client.CreateAction(t.Context(), connect.NewRequest(&actions.CreateActionRequest{Name: "created"}))
			require.NoError(t, err)
			assert.Equal(t, "created", created.Msg.GetAction().GetName())
			<-harness.observations
			<-harness.entries
			updated, err := client.UpdateAction(t.Context(), connect.NewRequest(&actions.UpdateActionRequest{Id: "00000000-0000-0000-0000-000000000022", Name: "updated"}))
			require.NoError(t, err)
			assert.Equal(t, "updated", updated.Msg.GetAction().GetName())
			<-harness.observations
			<-harness.entries
			deleted, err := client.DeleteAction(t.Context(), connect.NewRequest(&actions.DeleteActionRequest{Id: "00000000-0000-0000-0000-000000000023"}))
			require.NoError(t, err)
			assert.Equal(t, "00000000-0000-0000-0000-000000000023", deleted.Msg.GetAction().GetId())
			<-harness.observations
			<-harness.entries
		})
	}
}

func TestLocalHTTPProductionIPCStackErrorsAndCancellation(t *testing.T) {
	setupProductionTracing(t)
	harness := newProductionHarness(t)
	for name, client := range harness.clients() {
		t.Run(name, func(t *testing.T) {
			t.Run("missing auth follows IPC trust rule", func(t *testing.T) {
				resp, err := client.GetAction(t.Context(), connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000002"}}))
				require.NoError(t, err)
				assert.Equal(t, "00000000-0000-0000-0000-000000000002", resp.Msg.GetAction().GetId())
				observed := <-harness.observations
				<-harness.entries
				assert.Empty(t, observed.principal)
			})
			t.Run("invalid propagated auth", func(t *testing.T) {
				req := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000003"}})
				req.Header().Set("X-Ipc-Access-Token", "not-a-jwt")
				_, err := client.GetAction(t.Context(), req)
				require.Error(t, err)
				<-harness.entries
				assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
			})
			t.Run("validation", func(t *testing.T) {
				_, err := client.GetAction(t.Context(), connect.NewRequest(&actions.GetActionRequest{}))
				require.Error(t, err)
				<-harness.entries
				assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
			})
			t.Run("send limit", func(t *testing.T) {
				_, err := client.CreateAction(t.Context(), connect.NewRequest(&actions.CreateActionRequest{Name: string(make([]byte, productionTestSendLimit))}))
				require.Error(t, err)
				assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
			})
			t.Run("read limit", func(t *testing.T) {
				_, err := client.GetAction(t.Context(), connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000006"}}))
				require.Error(t, err)
				assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
				<-harness.observations
				<-harness.entries
			})
			t.Run("cancelled", func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_, err := client.GetAction(ctx, connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000004"}}))
				require.ErrorIs(t, err, context.Canceled)
			})
		})
	}
}

func TestLocalHTTPProductionIPCStackSampledLatency(t *testing.T) {
	if os.Getenv("IPC_V2_SAMPLE_LATENCY") == "" {
		t.Skip("set IPC_V2_SAMPLE_LATENCY=1 to collect production-stack percentiles")
	}
	samples := 1000
	if raw := os.Getenv("IPC_BENCH_SAMPLES"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		require.NoError(t, err)
		require.Positive(t, parsed)
		samples = parsed
	}
	setupProductionTracing(t)
	harness := newProductionHarness(t)
	harness.fixture.responseName = strings.Repeat("x", productionBenchmarkPayloadSize)
	token := unsignedProductionToken(t, "sample-principal")
	for name, client := range harness.clients() {
		t.Run(name, func(t *testing.T) {
			latencies := make([]time.Duration, samples)
			for i := range samples {
				req := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000007"}})
				req.Header().Set("X-Ipc-Access-Token", token)
				start := time.Now()
				_, err := client.GetAction(t.Context(), req)
				require.NoError(t, err)
				latencies[i] = time.Since(start)
				<-harness.observations
				<-harness.entries
			}
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			t.Logf("stack=production transport=%s samples=%d payload=Action.GetAction goos=%s goarch=%s go_version=%s gomaxprocs=%d p50=%s p95=%s p99=%s",
				name, samples, runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.GOMAXPROCS(0),
				productionPercentile(latencies, 50), productionPercentile(latencies, 95), productionPercentile(latencies, 99))
		})
	}
}

func productionPercentile(samples []time.Duration, percentile int) time.Duration {
	index := (len(samples)*percentile + 99) / 100
	if index < 1 {
		index = 1
	}
	return samples[index-1]
}

func BenchmarkLocalHTTPProductionIPCStack(b *testing.B) {
	harness := newProductionHarness(b)
	harness.fixture.responseName = strings.Repeat("x", productionBenchmarkPayloadSize)
	token := unsignedProductionToken(b, "benchmark-principal")
	for name, client := range harness.clients() {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				req := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: "00000000-0000-0000-0000-000000000005"}})
				req.Header().Set("X-Ipc-Access-Token", token)
				if _, err := client.GetAction(b.Context(), req); err != nil {
					b.Fatal(fmt.Errorf("production Action call: %w", err))
				}
				<-harness.observations
				<-harness.entries
			}
		})
	}
}
