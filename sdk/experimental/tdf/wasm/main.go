//go:build wasip1

// WASM core TDF module — compiled with TinyGo targeting wasip1.
//
// This is the entry point for the hybrid WASM TDF engine. All crypto
// operations are delegated to the host via the hostcrypto package;
// the TDF logic (manifest construction, ZIP packaging, integrity)
// runs inside the WASM sandbox.
//
// See: docs/adr/spike-wasm-core-tinygo-hybrid.md
package main

import (
	"strings"
	"unsafe"
)

// lastError holds the most recent error message for the host to retrieve.
var lastError string

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

//go:wasmexport get_error
func getError(outPtr, outCapacity uint32) uint32 {
	if lastError == "" {
		return 0
	}
	msg := lastError
	if uint32(len(msg)) > outCapacity {
		msg = msg[:outCapacity]
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(outPtr))), len(msg))
	copy(dst, msg)
	lastError = ""
	return uint32(len(msg))
}

//go:wasmexport tdf_encrypt
func tdfEncrypt(
	kasPubPtr, kasPubLen uint32,
	kasURLPtr, kasURLLen uint32,
	attrPtr, attrLen uint32,
	ptPtr, ptLen uint32,
	outPtr, outCapacity uint32,
) uint32 {
	kasPubPEM := ptrToString(kasPubPtr, kasPubLen)
	kasURL := ptrToString(kasURLPtr, kasURLLen)

	var attrs []string
	if attrLen > 0 {
		attrStr := ptrToString(attrPtr, attrLen)
		attrs = strings.Split(attrStr, "\n")
	}

	plaintext := ptrToBytes(ptPtr, ptLen)

	result, err := encrypt(kasPubPEM, kasURL, attrs, plaintext)
	if err != nil {
		lastError = err.Error()
		return 0
	}

	if uint32(len(result)) > outCapacity {
		lastError = "output buffer too small"
		return 0
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(outPtr))), len(result))
	copy(dst, result)
	return uint32(len(result))
}

// ── WASM memory helpers ─────────────────────────────────────────────

func ptrToString(ptr, length uint32) string {
	if length == 0 {
		return ""
	}
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), length)
}

func ptrToBytes(ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
}

func main() {
	// Required for wasip1 target; TDF operations are called via exports
}
