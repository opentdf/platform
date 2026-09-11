# Experimental local HTTP IPC adapter

This package implements the bounded adapter used by the opt-in Action-service IPC experiment. It dispatches the existing generated Connect client through the server's already-constructed in-process HTTP mux, so protobuf encoding, request shapes, handlers, and server interceptors remain unchanged. At startup, `server.ipc.transport: local-http-v2` binds only `SDK.Actions` to this adapter after the registered Action service descriptor and deployment mode have been validated. The default is `connect-v1`.

The adapter supports unary HTTP exchanges only, with identity encoding fixed at its transport boundary. It removes HTTP and Connect response-compression offers from the cloned server-facing headers, without changing caller headers. Compressed request bodies are rejected before handler dispatch, and a handler response labeled with a non-identity encoding is rejected rather than passed to the client. There is no compressed v2 mode. Response streaming, full duplex, hijacking, and custom clients that require `http.Flusher` are unsupported. Each call has independent pipe-backed flow (bounded by reader progress), and closing or cancelling a call releases its request body, response pipe, and server request context. Request header/control state is capped at one MiB. `Shutdown` rejects new work and drains existing calls without cancelling them; if its context expires, an arbitrary Go handler continues until it returns or the caller separately invokes `Close`. `Close` force-cancels the transport-owned contexts and I/O but cannot forcibly terminate arbitrary Go code. There is no adapter-wide admission limit or public tuning API.

The client has one explicit experimental compatibility coupling: a recovered local handler panic is translated to Connect `Internal`, matching the generated client's v1 HTTP/2 failure class before and after response commitment. It is never replayed through v1. A server-owned diagnostic hook records the procedure, panic type, and stack while intentionally excluding the panic value and request headers; clients receive only the generic internal error. No other network, context, malformed-body, or application error is remapped, and response streaming/backpressure remains unchanged.

Ordinary IPC uses the existing IPC server interceptor: it reconstructs supported metadata and propagated token state from serialized headers without signature/claims revalidation or general public-API authorization. Configured reauthentication routes (Rewrap by default) separately validate token/DPoP, and handler-owned domain checks remain separate. Requester attribution is not an executing-service identity or a globally authorized state. Nested tests deliberately prove that parsed auth, arbitrary values, incoming metadata, audit state, and span state do not cross directly; only supported serialized headers and interceptors reconstruct the nested server context.

The package benchmark harness compares v1-default, v1-compression-off, and the single v2-fixed-identity case, plus a TCP loopback server. The v1 compression-off fixture disables gzip in both Connect and the HTTP/2 transport; deleting request headers alone is insufficient because HTTP/2 can add gzip negotiation again. Wire-level coverage retains evidence that both v1 layers are disabled and verifies that a default generated client receives an identity response through v2 even when it advertises gzip. The harness offers raw and explicitly synthetic-wrapper cases and reports standard Go benchmark time, bytes, and allocations. The synthetic wrapper is not labeled or treated as the production middleware stack. `service/internal/server/localhttp_production_test.go` separately composes the actual server tracing, IPC authentication, protovalidation, and audit interceptors plus the actual client tracing, audit metadata, IPC metadata, and message-limit options for the same three identity/compression controls in its benchmark and sampled-latency coverage. The production measurement cases use the same Action payload, handler, middleware, limits, and instrumentation. Set `IPC_BENCH_PAYLOAD_BYTES` to control the package benchmark response size and use normal Go benchmark flags (including `-cpu`) for concurrency. Set `IPC_V2_SAMPLE_LATENCY=1` to run actual sampled percentile reporting; `IPC_BENCH_SAMPLES` controls sample count. Sample names state whether the synthetic wrapper or production stack is in use and include workload and Go/runtime environment metadata. Ordinary tests impose no timing threshold.

This experiment does not claim performance gains or accelerated support for downstream extensions. `SDK.Conn()`, all built-in SDK clients other than `SDK.Actions`, legacy gRPC dialers, remote connections, and custom downstream clients retain their existing v1/remote assembly. In core-only mode the startup inventory reports the retained remote ERS binding separately from local Connect v1 clients. The selector is read only at process startup: configuration reload can update the parsed value but does not rebind the constructed SDK; rollback requires setting `connect-v1` (or removing the opt-in) and restarting. `local-http-v2` is rejected outside a local IPC mode and when the Action service descriptor is absent. There is no federation capability publication, fallback execution mode, compression option, streaming support, or global admission setting.

## Focused startup and lifecycle evidence

`service/integration/TestAuthenticatedStartupInternalActionProbe` is a test-only full-platform probe. For each `connect-v1` and `local-http-v2` selector it starts the real `server.Start` flow in a helper process, registers a test-only core Connect service through `WithCoreServices`, and retains the startup-injected `RegistrationParams.SDK`. An authenticated public Probe RPC calls that SDK's `Actions.GetAction` and `Namespaces.GetNamespace`; both requests reach the real policy handlers and disposable PostgreSQL-backed storage. A hermetic OIDC discovery/JWKS server signs the public Bearer token, a forged token is rejected, and the valid token is verified by the platform. `WithIPCInterceptors` records the actual internal procedures and peers: Action dispatch occurs exactly once and uses `local-http-ipc` only for v2, while Namespace dispatch occurs exactly once and remains on v1. The helper adds no production route or protobuf API.

The integration package uses testcontainers for an ephemeral PostgreSQL port, provisions a unique per-selector policy schema, drops both schemas, terminates its named disposable container, and leaves the pre-existing isolated Keycloak fixture untouched. With Ryuk disabled, verify the daemon contents after the command. For the isolated Colima profile used during this experiment, run:

```sh
(
  . /tmp/opentdf-ipc-profile-ee1846/environment.sh
  export GOTOOLCHAIN=go1.25.14
  test "$DOCKER_HOST" = "unix:///Users/jschumacher/.colima/opentdf-ipc-tests-ee1846/docker.sock"
  test "$(go env GOVERSION)" = "go1.25.14"
  go env GOVERSION GOROOT
  cd service
  go test -timeout=180s -count=1 -run '^TestAuthenticatedStartupInternalActionProbe$' -v ./integration
  docker ps -a --format '{{.Names}}|{{.Status}}'
)
```

The lifecycle regressions are Docker-free:

```sh
(
  . /tmp/opentdf-ipc-profile-ee1846/environment.sh
  export GOTOOLCHAIN=go1.25.14
  test "$(go env GOVERSION)" = "go1.25.14"
  go env GOVERSION GOROOT
  cd service
  go test -timeout=60s -count=10 -run '^TestStop' ./internal/server
  go test -timeout=60s -count=10 -run 'Test(IPCTransportSelectionRemainsStartupOnlyAcrossConfigReload|StartLaterFailureRunsDeferredIPCResourceCleanup)' ./pkg/server
)
```

They compose active public and local IPC calls around `OpenTDFServer.Stop`: a public HTTP shutdown deadline does not prevent cooperative v2 drain or v1/v2 closure; a bounded local deadline force-closes transport-owned contexts and I/O but explicitly does not claim to stop arbitrary handler goroutines; and a failure injected after server/SDK construction exercises `Start`'s real deferred cleanup. The reload regression confirms that an already-constructed Action binding does not switch dynamically.

Remaining gaps are deliberate. No production service currently invokes the internally injected `SDK.Actions` client beyond constructing the binding, so this probe establishes startup and transport behavior rather than a production workload or performance benefit. It is not broad BDD/xtest coverage, does not measure production throughput or latency, and does not expand v2 beyond unary Action RPCs.
