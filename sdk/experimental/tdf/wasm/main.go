//go:build wasip1

// WASM core TDF module — compiled with TinyGo targeting wasip1.
//
// This is the entry point for the hybrid WASM TDF engine. All crypto
// operations are delegated to the host via the hostcrypto package;
// the TDF logic (manifest construction, ZIP packaging, key splitting,
// integrity) runs inside the WASM sandbox.
//
// EXPECTED TO FAIL under TinyGo until the spike work is complete.
// See: docs/adr/spike-wasm-core-tinygo-hybrid.md
//
// Blockers:
//   - lib/ocrypto → replaced by hostcrypto (go:wasmimport host functions)
//   - github.com/google/uuid → generate on host or use TinyGo-compatible lib
//   - protocol/go/policy → decouple from writer or provide lightweight types
//   - log/slog → replace with minimal logger or remove
package main

import (
	"context"
	"unsafe"

	"github.com/opentdf/platform/sdk/experimental/tdf"
	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/hostcrypto"
)

// ── Exported WASM functions ─────────────────────────────────────────
// Called by the host to perform TDF operations.

//go:wasmexport malloc
func wasmMalloc(size uint32) uint32 {
	buf := make([]byte, size)
	return uint32(uintptr(unsafe.Pointer(&buf[0])))
}

//go:wasmexport free
func wasmFree(_ uint32) {
	// No-op with leaking GC; tracked for future improvement
}

//go:wasmexport tdf_encrypt
func tdfEncrypt(
	kasPubPtr, kasPubLen uint32,
	kasURLPtr, kasURLLen uint32,
	attrPtr, attrLen uint32,
	ptPtr, ptLen uint32,
	outPtr, outCapacity uint32,
) uint32 {
	// Stub — spike will implement the full encrypt path here
	ctx := context.Background()

	// Validate that the tdf package is reachable
	w, err := tdf.NewWriter(ctx)
	if err != nil {
		return 0
	}
	_ = w

	// Validate that host crypto wrappers are linked
	_, err = hostcrypto.RandomBytes(32)
	if err != nil {
		return 0
	}

	return 0
}

func main() {
	// Required for wasip1 target; TDF operations are called via exports
}
