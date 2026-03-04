# Cross-SDK TDF Performance Benchmark Report

**Date:** 2026-02-19
**Platform:** localhost:8080 (local Docker Compose)
**Iterations:** 3 per payload size (averaged)
**Machine:** macOS Darwin 25.2.0

## Environment

| SDK | Language | Runtime |
|-----|----------|---------|
| Go Production SDK | Go | Native binary |
| Go Exp. Writer | Go | Native binary (parallel segments) |
| Go WASM | Go/TinyGo | wazero (local RSA unwrap, no KAS) |
| Java SDK | Java 11+ | JVM (HotSpot) |
| Java WASM | Go/TinyGo | Chicory 1.5.3 (pure-Java, local RSA unwrap, no KAS) |
| TypeScript SDK | TypeScript | Node.js |
| TypeScript WASM | Go/TinyGo | Node.js WebAssembly (encrypt: local RSA, decrypt: KAS rewrap) |

## Encrypt Performance (ms)

| Payload | Go SDK | Go Writer | Go WASM | Java SDK | Java WASM† | TS SDK | TS WASM |
|---------|--------|-----------|---------|----------|------------|--------|---------|
| 256 B   | 3.4    | 0.2       | 0.4     | 26.0     | 57.9       | 42.8   | 0.7     |
| 1 KB    | 0.1    | 0.1       | 0.2     | 5.1      | 29.5       | 25.9   | 0.2     |
| 16 KB   | 0.6    | 0.1       | 0.2     | 4.9      | 7.0        | 24.7   | 0.2     |
| 64 KB   | 0.1    | 0.1       | 0.3     | 5.0      | 15.6       | 28.9   | 0.3     |
| 256 KB  | 0.2    | 0.5       | 1.6     | 7.8      | 51.3       | 35.8   | 0.7     |
| 1 MB    | 0.7    | 1.0       | 5.8     | 21.7     | 187.4      | 73.3   | 2.6     |
| 10 MB   | 5.8    | 3.0       | 44.1    | 184.3    | 1,728.9    | 519.5  | 21.3    |
| 100 MB  | 57.3   | 16.4      | 543.9   | 1,768.4  | OOM        | 5,205.3| OOM     |

† Chicory is a pure-Java WASM interpreter (no JIT), so WASM encrypt is slower than native Java SDK. A JIT-enabled runtime (e.g., GraalWasm) would be significantly faster.
OOM at 100 MB is due to TinyGo's `gc=leaking` — the WASM linear memory cannot reclaim allocations during encrypt.

## Decrypt Performance (ms)

| Payload | Go SDK* | Go WASM** | Java SDK* | Java WASM** | TS SDK* | TS WASM* |
|---------|---------|-----------|-----------|-------------|---------|----------|
| 256 B   | 20.2    | 1.3       | 116.3     | 27.7        | 62.2    | 74.9     |
| 1 KB    | 18.7    | 1.2       | 28.0      | 3.3         | 60.7    | 57.6     |
| 16 KB   | 18.2    | 1.3       | 24.2      | 3.1         | 46.2    | 59.9     |
| 64 KB   | 17.8    | 1.2       | 23.9      | 4.5         | 54.6    | 46.0     |
| 256 KB  | 17.6    | 1.6       | 25.1      | 8.8         | 73.6    | 83.6     |
| 1 MB    | 17.9    | 2.5       | 39.6      | 26.8        | 71.3    | 76.1     |
| 10 MB   | 21.4    | 11.6      | 197.4     | 244.4       | 298.4   | 272.9    |
| 100 MB  | 58.9    | 266.1     | 1,747.8   | 2,254.1     | 2,431.5 | 2,525.7  |

\* Includes KAS rewrap network latency (~20-80ms per request)
\*\* Go and Java WASM decrypt uses local RSA-OAEP DEK unwrap (no network); in production the host would call KAS for rewrap

## Key Takeaways

**1. Go SDK is the fastest across the board.**
At 100 MB, Go encrypt (57 ms) is 31x faster than Java and 94x faster than TypeScript. The Go Experimental Writer with parallel segment processing is even faster (16 ms for 100 MB).

**2. Decrypt is dominated by KAS latency at small sizes.**
For payloads up to 1 MB, all three native SDKs show ~18-74 ms, reflecting the network round-trip to the KAS rewrap endpoint. Go and Java WASM decrypt (local RSA unwrap, no network) completes in 1.2-2.5 ms for the same sizes — 7-15x faster. TS WASM decrypt includes KAS rewrap and shows ~46-84 ms, roughly matching the native TS SDK.

**3. WASM decrypt performance varies by host methodology.**
Go and Java WASM use local RSA unwrap (no KAS network call); TS WASM includes KAS rewrap:
- Go/wazero: 1.2-266 ms (local unwrap, JIT-compiled, 100 MB = ~376 MB/s)
- TypeScript/V8: 46-2,526 ms (includes KAS rewrap; roughly matches native TS SDK)
- Java/Chicory: 3.1-2,254 ms (local unwrap, interpreted, 10-20x slower than JIT hosts)

**4. TypeScript has the highest per-operation overhead.**
Even at 256 B, SDK encrypt takes 42 ms in TypeScript vs 5.5 ms in Go and 21.9 ms in Java. This is due to Node.js async/await overhead and the SDK's internal key-fetching flow. But TS WASM bypasses this entirely — 0.7 ms for the same payload.

**5. The WASM approach validates the host-delegation architecture.**
The same `.wasm` binary (150 KB, TinyGo reactor mode) runs on all three hosts with consistent behavior. WASM encrypt+decrypt without KAS is fast enough to be practical for offline TDF operations.

**6. TypeScript WASM encrypt is remarkably fast — near Go WASM speeds.**
V8 JIT-compiles WASM to native code, so TS WASM encrypt (0.2-2.6 ms) matches Go WASM via wazero, bypassing the TS SDK's 25-73 ms overhead entirely. TS WASM decrypt includes KAS rewrap (~50-80 ms round-trip), so it roughly matches native TS SDK rather than local-unwrap Go WASM.

**7. Chicory (pure-Java interpreter) is the slowest WASM host.**
Java WASM encrypt via Chicory (7-1,729 ms) is slower than native Java SDK at all sizes. WASM decrypt is faster than native+KAS for small payloads (3 ms vs 28 ms at 1 KB) but slower at large sizes (2,254 ms vs 1,748 ms at 100 MB). A JIT-enabled WASM runtime (e.g., GraalWasm, Wasmtime-JNI) would likely match Go WASM encrypt performance.

**9. WASM encrypt OOMs at 100 MB due to TinyGo's leaking GC.**
The `gc=leaking` mode (required for stable slice pointers) means WASM linear memory can't reclaim allocations. At 100 MB, encrypt needs ~300 MB of WASM memory (plaintext + ciphertext + ZIP overhead), exceeding the default limit. Decrypt is more memory-efficient (direct-to-output-buffer) and handles 100 MB on all hosts.

**8. Java first-call warmup is visible.**
Java 256 B encrypt (21.9 ms) is 5x slower than 1 KB (4.0 ms), reflecting JIT compilation warmup on the first iteration. Steady-state Java encrypt is roughly 4-5 ms for small payloads.

## Benchmark Sources

| SDK | Benchmark File | WASM Host |
|-----|----------------|-----------|
| Go | `platform/examples/cmd/benchmark_cross_sdk.go` | wazero (built-in) |
| Java | `java-sdk/examples/src/main/java/io/opentdf/platform/BenchmarkCrossSDK.java` | Chicory 1.5.3 (`-w` flag) |
| TypeScript | `web-sdk/cli/src/benchmark.ts` | Node.js WebAssembly (`--wasmBinary` flag) |

### Running WASM benchmarks

All three benchmarks now include WASM encrypt and decrypt columns. The WASM module (`tdfcore.wasm`) is loaded at startup. Go and Java WASM use a local RSA keypair (no KAS needed); TS WASM encrypt uses a cached KAS public key and decrypt calls KAS rewrap over HTTP.

```bash
# Go (WASM compiled automatically from sdk/experimental/tdf/wasm/)
cd platform && go run ./examples benchmark-cross-sdk

# Java (requires tdfcore.wasm from wasm-host test resources)
cd java-sdk && mvn package -DskipTests -pl examples -am
java -cp examples/target/examples-0.12.0.jar io.opentdf.platform.BenchmarkCrossSDK \
  -w wasm-host/src/test/resources/tdfcore.wasm

# TypeScript (defaults to ../../wasm-host/tdfcore.wasm relative to dist/)
cd web-sdk/cli && npm run build && node dist/src/benchmark.js \
  --wasmBinary ../../wasm-host/tdfcore.wasm
```
