# TDF WASM Canary Build
#
# Builds canary programs with TinyGo to validate WASM compatibility.
# See README.md for prerequisites.

.PHONY: all toolcheck generate build run clean \
        base64hex zipwrite tinyjson iocontext stdjson

TINYGO_FLAGS = -target=wasip1 -no-debug -scheduler=none -gc=leaking
OUT_DIR      = _out

# Canaries expected to pass (build + run)
PASS_CANARIES = base64hex zipwrite tinyjson
# Canaries expected to fail (build-only, allow failure)
FAIL_CANARIES = iocontext stdjson

all: toolcheck build

toolcheck:
	@echo "Checking for required tools..."
	@which tinygo > /dev/null 2>&1 || \
		(echo "error: tinygo not found" && \
		 echo "  macOS:  brew tap tinygo-org/tools && brew install tinygo" && \
		 echo "  Linux:  wget https://github.com/tinygo-org/tinygo/releases/download/v0.37.0/tinygo_0.37.0_amd64.deb && sudo dpkg -i tinygo_0.37.0_amd64.deb" && \
		 exit 1)
	@which tinyjson > /dev/null 2>&1 || \
		(echo "error: tinyjson not found" && \
		 echo "  Install: go install github.com/CosmWasm/tinyjson/...@latest" && \
		 exit 1)
	@echo "  tinygo:   $$(tinygo version)"
	@echo "  tinyjson: $$(which tinyjson)"

generate:
	@echo "Regenerating tinyjson codegen..."
	cd tinyjson && GOWORK=off go generate ./types/

build: toolcheck $(PASS_CANARIES)
	@echo "All passing canaries built successfully."

run: build
	@which wasmtime > /dev/null 2>&1 || \
		(echo "error: wasmtime not found — install with: curl https://wasmtime.dev/install.sh -sSf | bash" && exit 1)
	@for c in $(PASS_CANARIES); do \
		echo "Running $$c..."; \
		wasmtime $(OUT_DIR)/$$c.wasm || exit 1; \
	done
	@echo "All canaries passed."

# ── Individual canary targets ────────────────────────────────

base64hex: $(OUT_DIR)
	tinygo build $(TINYGO_FLAGS) -o $(OUT_DIR)/base64hex.wasm ./base64hex

zipwrite: $(OUT_DIR)
	tinygo build $(TINYGO_FLAGS) -o $(OUT_DIR)/zipwrite.wasm ./zipwrite

tinyjson: $(OUT_DIR)
	cd tinyjson && GOWORK=off tinygo build $(TINYGO_FLAGS) -o ../$(OUT_DIR)/tinyjson.wasm .

iocontext: $(OUT_DIR)
	-tinygo build $(TINYGO_FLAGS) -o $(OUT_DIR)/iocontext.wasm ./iocontext

stdjson: $(OUT_DIR)
	-tinygo build $(TINYGO_FLAGS) -o $(OUT_DIR)/stdjson.wasm ./stdjson

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

clean:
	rm -rf $(OUT_DIR)
