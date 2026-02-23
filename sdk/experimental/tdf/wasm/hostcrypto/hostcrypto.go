//go:build wasip1

// Package hostcrypto provides typed Go wrappers for WASM host-imported
// functions. All crypto operations are delegated to the host runtime
// (Wazero, browser, etc.) via go:wasmimport. The I/O hooks (read_input,
// write_output) are also wrapped here to avoid colliding with stdlib "io".
//
// See docs/adr/spike-wasm-core-tinygo-hybrid.md for the full ABI spec.
package hostcrypto

import (
	"errors"
	"unsafe"
)

// errSentinel is the uint32 value returned by host functions on error.
const errSentinel = 0xFFFFFFFF

// errGetLastError is returned when getLastError itself fails.
var errGetLastError = errors.New("hostcrypto: host error (get_last_error failed)")

// ── Raw host imports (private) ──────────────────────────────────────

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

// ── Internal helpers ────────────────────────────────────────────────

// slicePtr returns a uint32 pointer into WASM linear memory for the
// first element of b. Returns 0 for nil or empty slices.
//
// Safety: with gc=leaking the GC never moves allocations, so the
// pointer remains valid for the lifetime of the slice. This assumption
// must be revisited if the GC strategy changes.
func slicePtr(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&b[0])))
}

// getLastError retrieves the most recent error message from the host.
// The host clears the error after reading.
func getLastError() error {
	buf := make([]byte, 1024)
	n := _get_last_error(slicePtr(buf), uint32(len(buf)))
	if n == 0 || n == errSentinel {
		return errGetLastError
	}
	return errors.New("hostcrypto: " + string(buf[:n]))
}

// ── Exported wrappers ───────────────────────────────────────────────

// RandomBytes returns n cryptographically random bytes from the host.
func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	result := _random_bytes(slicePtr(buf), uint32(n))
	if result == errSentinel {
		return nil, getLastError()
	}
	return buf, nil
}

// AesGcmEncrypt encrypts plaintext with AES-256-GCM using the given key.
// The returned ciphertext is [nonce (12) || ciphertext || tag (16)].
// Key must be 32 bytes (AES-256).
func AesGcmEncrypt(key, plaintext []byte) ([]byte, error) {
	outLen := len(plaintext) + 28 // 12 nonce + 16 tag
	out := make([]byte, outLen)
	result := _aes_gcm_encrypt(
		slicePtr(key), uint32(len(key)),
		slicePtr(plaintext), uint32(len(plaintext)),
		slicePtr(out),
	)
	if result == errSentinel {
		return nil, getLastError()
	}
	return out[:result], nil
}

// AesGcmEncryptInto encrypts plaintext with AES-256-GCM directly into the
// caller-provided output buffer, avoiding an intermediate allocation.
// Returns the number of ciphertext bytes written (plaintext + 28).
// out must be at least len(plaintext)+28 bytes.
func AesGcmEncryptInto(key, plaintext, out []byte) (int, error) {
	needed := len(plaintext) + 28 // 12 nonce + 16 tag
	if len(out) < needed {
		return 0, errors.New("hostcrypto: output buffer too small for AES-GCM encrypt")
	}
	result := _aes_gcm_encrypt(
		slicePtr(key), uint32(len(key)),
		slicePtr(plaintext), uint32(len(plaintext)),
		slicePtr(out),
	)
	if result == errSentinel {
		return 0, getLastError()
	}
	return int(result), nil
}

// AesGcmDecrypt decrypts AES-256-GCM ciphertext.
// Input must be [nonce (12) || ciphertext || tag (16)].
// Key must be 32 bytes (AES-256).
func AesGcmDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 28 {
		return nil, errors.New("hostcrypto: ciphertext too short for AES-GCM (need >= 28 bytes)")
	}
	outLen := len(ciphertext) - 28
	out := make([]byte, outLen)
	result := _aes_gcm_decrypt(
		slicePtr(key), uint32(len(key)),
		slicePtr(ciphertext), uint32(len(ciphertext)),
		slicePtr(out),
	)
	if result == errSentinel {
		return nil, getLastError()
	}
	return out[:result], nil
}

// AesGcmDecryptInto decrypts AES-256-GCM ciphertext directly into the
// caller-provided output buffer, avoiding an intermediate allocation.
// Returns the number of plaintext bytes written.
// out must be at least len(ciphertext)-28 bytes.
func AesGcmDecryptInto(key, ciphertext, out []byte) (int, error) {
	if len(ciphertext) < 28 {
		return 0, errors.New("hostcrypto: ciphertext too short for AES-GCM (need >= 28 bytes)")
	}
	needed := len(ciphertext) - 28
	if len(out) < needed {
		return 0, errors.New("hostcrypto: output buffer too small for AES-GCM decrypt")
	}
	result := _aes_gcm_decrypt(
		slicePtr(key), uint32(len(key)),
		slicePtr(ciphertext), uint32(len(ciphertext)),
		slicePtr(out),
	)
	if result == errSentinel {
		return 0, getLastError()
	}
	return int(result), nil
}

// HmacSHA256 computes HMAC-SHA256 over data using key.
// Returns exactly 32 bytes.
func HmacSHA256(key, data []byte) ([]byte, error) {
	out := make([]byte, 32)
	result := _hmac_sha256(
		slicePtr(key), uint32(len(key)),
		slicePtr(data), uint32(len(data)),
		slicePtr(out),
	)
	if result == errSentinel {
		return nil, getLastError()
	}
	return out[:result], nil
}

// RsaOaepSha1Encrypt encrypts plaintext with RSA-OAEP (SHA-1 hash, SHA-1 MGF1).
// pubPEM is the PEM-encoded RSA public key.
func RsaOaepSha1Encrypt(pubPEM string, plaintext []byte) ([]byte, error) {
	pub := []byte(pubPEM)
	out := make([]byte, 256) // RSA-2048 output
	result := _rsa_oaep_sha1_encrypt(
		slicePtr(pub), uint32(len(pub)),
		slicePtr(plaintext), uint32(len(plaintext)),
		slicePtr(out),
	)
	if result == errSentinel {
		return nil, getLastError()
	}
	return out[:result], nil
}

// RsaOaepSha1Decrypt decrypts ciphertext with RSA-OAEP (SHA-1 hash, SHA-1 MGF1).
// privPEM is the PEM-encoded RSA private key.
func RsaOaepSha1Decrypt(privPEM string, ciphertext []byte) ([]byte, error) {
	priv := []byte(privPEM)
	out := make([]byte, 256) // RSA-2048 output
	result := _rsa_oaep_sha1_decrypt(
		slicePtr(priv), uint32(len(priv)),
		slicePtr(ciphertext), uint32(len(ciphertext)),
		slicePtr(out),
	)
	if result == errSentinel {
		return nil, getLastError()
	}
	return out[:result], nil
}

// RsaGenerateKeypair generates an RSA keypair of the specified bit size.
// Returns PEM-encoded private and public keys.
func RsaGenerateKeypair(bits int) (privPEM, pubPEM []byte, err error) {
	privBuf := make([]byte, 4096)
	pubBuf := make([]byte, 4096)
	pubLenBuf := make([]byte, 4) // host writes pub key length here (little-endian uint32)

	privLen := _rsa_generate_keypair(
		uint32(bits),
		slicePtr(privBuf),
		slicePtr(pubBuf),
		slicePtr(pubLenBuf),
	)
	if privLen == errSentinel {
		return nil, nil, getLastError()
	}

	// Decode public key length from little-endian uint32.
	pubLen := uint32(pubLenBuf[0]) |
		uint32(pubLenBuf[1])<<8 |
		uint32(pubLenBuf[2])<<16 |
		uint32(pubLenBuf[3])<<24

	return privBuf[:privLen], pubBuf[:pubLen], nil
}
