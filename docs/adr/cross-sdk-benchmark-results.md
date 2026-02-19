# Cross-SDK TDF Performance Benchmark Report

**Date:** 2026-02-19
**Platform:** localhost:8080 (local Docker Compose)
**Iterations:** 5 per payload size (averaged)
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
| TypeScript WASM | Go/TinyGo | Node.js WebAssembly (local RSA unwrap, no KAS) |

## Encrypt Performance (ms)

| Payload | Go SDK | Go Writer | Go WASM | Java SDK | Java WASM† | TS SDK | TS WASM |
|---------|--------|-----------|---------|----------|------------|--------|---------|
| 256 B   | 2.2    | 0.1       | 0.3     | 17.3     | 57.7       | 40.0   | 0.7     |
| 1 KB    | 0.4    | 0.1       | 0.2     | 4.1      | 49.3       | 25.6   | 0.2     |
| 16 KB   | 0.1    | 0.1       | 0.2     | 4.6      | 6.9        | 26.1   | 0.2     |
| 64 KB   | 0.4    | 0.1       | 0.9     | 4.4      | 15.2       | 28.0   | 0.3     |
| 256 KB  | 0.2    | 0.3       | 1.6     | 8.3      | 40.5       | 36.5   | 0.8     |
| 1 MB    | 0.6    | 1.2       | 4.5     | 22.5     | 145.3      | 72.6   | 2.8     |
| 10 MB   | 5.8    | 3.3       | 47.1    | 188.6    | —          | 514.3  | —       |
| 100 MB  | 48.7   | 19.7      | 485.3   | 1,799.0  | —          | 5,046.5| —       |

† Chicory is a pure-Java WASM interpreter (no JIT), so WASM encrypt is slower than native Java SDK. A JIT-enabled runtime (e.g., GraalWasm) would be significantly faster.

## Decrypt Performance (ms)

| Payload | Go SDK* | Go WASM** | Java SDK* | Java WASM** | TS SDK* | TS WASM** |
|---------|---------|-----------|-----------|-------------|---------|-----------|
| 256 B   | 32.9    | 1.4       | 58.7      | ‡           | 76.5    | ‡         |
| 1 KB    | 22.6    | 1.3       | 22.5      | ‡           | 59.4    | ‡         |
| 16 KB   | 23.8    | 1.4       | 26.0      | ‡           | 77.2    | ‡         |
| 64 KB   | 21.3    | 1.3       | 27.2      | ‡           | 52.8    | ‡         |
| 256 KB  | 22.9    | 1.5       | 26.4      | ‡           | 68.2    | ‡         |
| 1 MB    | 25.8    | 4.4       | 41.5      | ‡           | 76.4    | ‡         |
| 10 MB   | 24.5    | 19.6      | 205.0     | ‡           | 301.3   | ‡         |
| 100 MB  | 81.5    | 385.0     | 1,781.7   | ‡           | 2,368.5 | ‡         |

\* Includes KAS rewrap network latency (~20-30ms per request)
\*\* WASM decrypt uses local RSA-OAEP DEK unwrap (no network); in production the host would call KAS for rewrap
‡ The pre-built `tdfcore.wasm` in java-sdk and web-sdk only exports `tdf_encrypt`; `tdf_decrypt` is not yet included. The Go benchmark compiles its own WASM binary from source which includes both. WASM decrypt benchmarks for Java and TypeScript require rebuilding the WASM binary with decrypt support.

## Key Takeaways

**1. Go SDK is the fastest across the board.**
At 100 MB, Go encrypt is 37x faster than Java and 104x faster than TypeScript. The Go Experimental Writer with parallel segment processing is even faster (19.7 ms for 100 MB).

**2. Decrypt is dominated by KAS latency at small sizes.**
For payloads up to 1 MB, all three SDKs with KAS show ~20-80 ms, reflecting the network round-trip to the KAS rewrap endpoint. The actual crypto work is minimal — the WASM decrypt (no network) completes in 1.3-4.4 ms for the same sizes.

**3. Large-payload decrypt scales linearly with data size.**
Once payloads exceed 1 MB and the KAS overhead becomes proportionally small, the raw crypto throughput matters:
- Go: ~1.2 GB/s effective decrypt throughput
- Java: ~56 MB/s
- TypeScript: ~42 MB/s
- WASM: ~260 MB/s (but without KAS overhead)

**4. TypeScript has the highest per-operation overhead.**
Even at 256 B, encrypt takes 40 ms in TypeScript vs 2.2 ms in Go and 17.3 ms in Java. This is likely due to Node.js startup costs, async/await overhead, and the SDK's internal key-fetching flow.

**5. The WASM approach validates the host-delegation architecture.**
WASM encrypt scales at ~10x the Go production SDK cost (expected given the host ABI call overhead), but decrypt without KAS is extremely fast, demonstrating that the WASM core engine can handle the TDF crypto pipeline efficiently once the DEK is available.

**6. TypeScript WASM is remarkably fast — near Go WASM speeds.**
Node.js V8 JIT-compiles WASM to native code, so TS WASM encrypt (0.2-2.8 ms) matches Go WASM via wazero (0.2-4.5 ms). This validates the architecture: the same `.wasm` binary achieves consistent performance across JIT-enabled hosts. The TS SDK's 25-73 ms overhead is entirely in the JavaScript SDK layer, not in the crypto.

**7. Chicory (pure-Java interpreter) is the slowest WASM host.**
Java WASM encrypt via Chicory (6.9-145.3 ms) is slower than even the native Java SDK (4.1-22.5 ms) at most sizes. This is expected for a pure interpreter with no JIT. A JIT-enabled WASM runtime (e.g., GraalWasm, Wasmtime-JNI) would likely match or beat the native SDK.

**8. Java first-call warmup is visible.**
Java 256 B encrypt (17.3 ms) is 4x slower than 1 KB (4.1 ms), reflecting JIT compilation warmup on the first iteration. Steady-state Java encrypt is roughly 4-5 ms for small payloads.

## Benchmark Sources

| SDK | Benchmark File | WASM Host |
|-----|----------------|-----------|
| Go | `platform/examples/cmd/benchmark_cross_sdk.go` | wazero (built-in) |
| Java | `java-sdk/examples/src/main/java/io/opentdf/platform/BenchmarkCrossSDK.java` | Chicory 1.5.3 (`-w` flag) |
| TypeScript | `web-sdk/cli/src/benchmark.ts` | Node.js WebAssembly (`--wasmBinary` flag) |

### Running WASM benchmarks

All three benchmarks now include WASM encrypt and decrypt columns. The WASM module (`tdfcore.wasm`) is loaded at startup; WASM encrypt/decrypt use a local RSA keypair (no KAS needed for the WASM path).

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
