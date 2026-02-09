// Canary: go:wasmimport / go:wasmexport directives
// Validates that TinyGo can compile a WASM module with host-imported
// crypto functions and exported TDF entry points. This is the core
// pattern for the hybrid architecture.
//
// NOTE: This only tests compilation, not execution — the host functions
// have no implementation and will trap if called.
package main

import "unsafe"

// ── Host-imported crypto functions ──────────────────────────────────
// These would be provided by the Wazero host (Go) or browser (JS).

//go:wasmimport crypto random_bytes
func _random_bytes(out_ptr, n uint32) uint32

//go:wasmimport crypto aes_gcm_encrypt
func _aes_gcm_encrypt(key_ptr, key_len, pt_ptr, pt_len, out_ptr uint32) uint32

//go:wasmimport crypto aes_gcm_decrypt
func _aes_gcm_decrypt(key_ptr, key_len, ct_ptr, ct_len, out_ptr uint32) uint32

//go:wasmimport crypto hmac_sha256
func _hmac_sha256(key_ptr, key_len, data_ptr, data_len, out_ptr uint32) uint32

//go:wasmimport crypto rsa_oaep_sha1_encrypt
func _rsa_oaep_sha1_encrypt(pub_ptr, pub_len, pt_ptr, pt_len, out_ptr uint32) uint32

//go:wasmimport crypto rsa_oaep_sha1_decrypt
func _rsa_oaep_sha1_decrypt(priv_ptr, priv_len, ct_ptr, ct_len, out_ptr uint32) uint32

//go:wasmimport crypto rsa_generate_keypair
func _rsa_generate_keypair(bits, priv_out, pub_out, pub_len_ptr uint32) uint32

//go:wasmimport crypto get_last_error
func _get_last_error(out_ptr, out_capacity uint32) uint32

// ── Exported WASM functions ─────────────────────────────────────────
// These are called by the host to perform TDF operations.

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
	return 0
}

func main() {
	// Required for wasip1 target; TDF operations are called via exports
}
