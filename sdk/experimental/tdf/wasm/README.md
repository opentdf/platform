# TDF WASM Core Engine — Canary Programs

Canary programs that validate TinyGo compatibility for the WASM core engine
spike (SDK-WASM-1). Each canary exercises a specific set of Go stdlib or
third-party packages under TinyGo compilation.

See [`docs/adr/spike-wasm-core-tinygo-hybrid.md`](../../../../docs/adr/spike-wasm-core-tinygo-hybrid.md)
for the full spike plan.

## Prerequisites

### Go

Go 1.24+ is required (same as the main project).

### TinyGo

**macOS (Homebrew):**

```sh
brew tap tinygo-org/tools
brew install tinygo
```

**Linux (deb):**

```sh
wget https://github.com/tinygo-org/tinygo/releases/download/v0.37.0/tinygo_0.37.0_amd64.deb
sudo dpkg -i tinygo_0.37.0_amd64.deb
```

Verify:

```sh
tinygo version
```

CI uses TinyGo **v0.37.0**. Homebrew may install a newer version; that's fine.

### tinyjson (codegen only)

Required only for regenerating tinyjson codegen output:

```sh
go install github.com/CosmWasm/tinyjson/...@latest
```

### wasmtime (optional, for running .wasm binaries locally)

```sh
curl https://wasmtime.dev/install.sh -sSf | bash
```

## Canary Programs

| Canary | Status | Description |
|--------|--------|-------------|
| `base64hex/` | pass | `encoding/base64`, `encoding/hex` |
| `zipwrite/` | pass | `encoding/binary`, `hash/crc32`, `bytes`, `sort`, `sync` |
| `tinyjson/` | pass | tinyjson codegen manifest + assertion round-trip |
| `iocontext/` | fail | `io`, `context`, `strings`, `strconv`, `fmt`, `errors` |
| `stdjson/` | fail | `encoding/json` (superseded by `tinyjson/`) |

The root `wasm/main.go` is the full WASM module stub (expected to fail until
the spike is complete).

## Building

```sh
make toolcheck    # verify tinygo + tinyjson are installed
make all          # build all canaries to .wasm
make run          # build + run passing canaries with wasmtime
make tinyjson     # build just the tinyjson canary
make clean        # remove built .wasm files
```

To regenerate tinyjson codegen (after modifying struct definitions):

```sh
make generate
```
