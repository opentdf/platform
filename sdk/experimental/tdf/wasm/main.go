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

// allocations keeps malloc'd buffers reachable so the GC doesn't reclaim
// memory that the host has written data into between calls.
var allocations [][]byte

// ── Exported WASM functions ─────────────────────────────────────────
// Called by the host to perform TDF operations.

//export tdf_malloc
func wasmMalloc(size uint32) uint32 {
	buf := make([]byte, size)
	allocations = append(allocations, buf)
	return uint32(uintptr(unsafe.Pointer(&buf[0])))
}

//export tdf_free
func wasmFree(_ uint32) {
	// No-op with leaking GC; tracked for future improvement
}

//export get_error
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

//export tdf_encrypt
func tdfEncrypt(
	kasPubPtr, kasPubLen uint32,
	kasURLPtr, kasURLLen uint32,
	attrPtr, attrLen uint32,
	plaintextSize uint64,
	integrityAlg, segIntegrityAlg uint32,
	segmentSize uint32,
) uint32 {
	kasPubPEM := ptrToString(kasPubPtr, kasPubLen)
	kasURL := ptrToString(kasURLPtr, kasURLLen)

	var attrs []string
	if attrLen > 0 {
		attrStr := ptrToString(attrPtr, attrLen)
		attrs = strings.Split(attrStr, "\n")
	}

	totalWritten, err := encryptStream(kasPubPEM, kasURL, attrs, int64(plaintextSize), int(integrityAlg), int(segIntegrityAlg), int(segmentSize))
	if err != nil {
		lastError = err.Error()
		return 0
	}

	return uint32(totalWritten)
}

//export tdf_decrypt
func tdfDecrypt(
	tdfPtr, tdfLen uint32,
	dekPtr, dekLen uint32,
	outPtr, outCapacity uint32,
) uint32 {
	tdfData := ptrToSlice(tdfPtr, tdfLen)
	dek := ptrToSlice(dekPtr, dekLen)
	outBuf := ptrToSlice(outPtr, outCapacity)

	n, err := decrypt(tdfData, dek, outBuf)
	if err != nil {
		lastError = err.Error()
		return 0
	}

	return uint32(n)
}

// ── WASM memory helpers ─────────────────────────────────────────────

func ptrToString(ptr, length uint32) string {
	if length == 0 {
		return ""
	}
	// Copy into a Go-managed string so the result stays valid even if the
	// original malloc'd buffer is reclaimed between host calls.
	src := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
	return string(src)
}

// ptrToSlice returns a zero-copy []byte view over WASM linear memory.
// Safe when the backing allocation stays live for the duration of the call
// (e.g. tdf_malloc'd buffers pinned in allocations[]).
func ptrToSlice(ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
}

func main() {
	// Required for wasip1 target; TDF operations are called via exports
}
