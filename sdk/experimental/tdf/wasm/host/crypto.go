package host

import (
	"context"
	"encoding/binary"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// RegisterCrypto instantiates the "crypto" host module on the given
// wazero.Runtime. Returns the module closer.
func RegisterCrypto(ctx context.Context, rt wazero.Runtime) (api.Closer, error) {
	return rt.NewHostModuleBuilder("crypto").
		NewFunctionBuilder().WithFunc(hostRandomBytes).Export("random_bytes").
		NewFunctionBuilder().WithFunc(hostAesGcmEncrypt).Export("aes_gcm_encrypt").
		NewFunctionBuilder().WithFunc(hostAesGcmDecrypt).Export("aes_gcm_decrypt").
		NewFunctionBuilder().WithFunc(hostHmacSHA256).Export("hmac_sha256").
		NewFunctionBuilder().WithFunc(hostRsaOaepSha1Encrypt).Export("rsa_oaep_sha1_encrypt").
		NewFunctionBuilder().WithFunc(hostRsaOaepSha1Decrypt).Export("rsa_oaep_sha1_decrypt").
		NewFunctionBuilder().WithFunc(hostRsaGenerateKeypair).Export("rsa_generate_keypair").
		NewFunctionBuilder().WithFunc(hostGetLastError).Export("get_last_error").
		Instantiate(ctx)
}

// random_bytes(out_ptr, n uint32) -> uint32
func hostRandomBytes(_ context.Context, mod api.Module, outPtr, n uint32) uint32 {
	buf, err := ocrypto.RandomBytes(int(n))
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	if !writeBytes(mod, outPtr, buf) {
		setLastError(errOOB)
		return errSentinel
	}
	return n
}

// aes_gcm_encrypt(key_ptr, key_len, pt_ptr, pt_len, out_ptr) -> uint32
func hostAesGcmEncrypt(_ context.Context, mod api.Module, keyPtr, keyLen, ptPtr, ptLen, outPtr uint32) uint32 {
	key := readBytes(mod, keyPtr, keyLen)
	pt := readBytes(mod, ptPtr, ptLen)
	if key == nil {
		setLastError(errReadKey)
		return errSentinel
	}

	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	ct, err := aesGcm.Encrypt(pt)
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	if !writeBytes(mod, outPtr, ct) {
		setLastError(errOOB)
		return errSentinel
	}
	return uint32(len(ct))
}

// aes_gcm_decrypt(key_ptr, key_len, ct_ptr, ct_len, out_ptr) -> uint32
func hostAesGcmDecrypt(_ context.Context, mod api.Module, keyPtr, keyLen, ctPtr, ctLen, outPtr uint32) uint32 {
	key := readBytes(mod, keyPtr, keyLen)
	ct := readBytes(mod, ctPtr, ctLen)
	if key == nil {
		setLastError(errReadKey)
		return errSentinel
	}
	if ct == nil {
		setLastError(errReadCT)
		return errSentinel
	}

	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	pt, err := aesGcm.Decrypt(ct)
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	if !writeBytes(mod, outPtr, pt) {
		setLastError(errOOB)
		return errSentinel
	}
	return uint32(len(pt))
}

// hmac_sha256(key_ptr, key_len, data_ptr, data_len, out_ptr) -> uint32
func hostHmacSHA256(_ context.Context, mod api.Module, keyPtr, keyLen, dataPtr, dataLen, outPtr uint32) uint32 {
	key := readBytes(mod, keyPtr, keyLen)
	data := readBytes(mod, dataPtr, dataLen)
	if key == nil {
		setLastError(errReadKey)
		return errSentinel
	}

	mac := ocrypto.CalculateSHA256Hmac(key, data)
	if !writeBytes(mod, outPtr, mac) {
		setLastError(errOOB)
		return errSentinel
	}
	return uint32(len(mac))
}

// rsa_oaep_sha1_encrypt(pub_ptr, pub_len, pt_ptr, pt_len, out_ptr) -> uint32
func hostRsaOaepSha1Encrypt(_ context.Context, mod api.Module, pubPtr, pubLen, ptPtr, ptLen, outPtr uint32) uint32 {
	pubPEM := readBytes(mod, pubPtr, pubLen)
	pt := readBytes(mod, ptPtr, ptLen)
	if pubPEM == nil {
		setLastError(errReadKey)
		return errSentinel
	}

	enc, err := ocrypto.NewAsymEncryption(string(pubPEM))
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	ct, err := enc.Encrypt(pt)
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	if !writeBytes(mod, outPtr, ct) {
		setLastError(errOOB)
		return errSentinel
	}
	return uint32(len(ct))
}

// rsa_oaep_sha1_decrypt(priv_ptr, priv_len, ct_ptr, ct_len, out_ptr) -> uint32
func hostRsaOaepSha1Decrypt(_ context.Context, mod api.Module, privPtr, privLen, ctPtr, ctLen, outPtr uint32) uint32 {
	privPEM := readBytes(mod, privPtr, privLen)
	ct := readBytes(mod, ctPtr, ctLen)
	if privPEM == nil {
		setLastError(errReadKey)
		return errSentinel
	}
	if ct == nil {
		setLastError(errReadCT)
		return errSentinel
	}

	dec, err := ocrypto.NewAsymDecryption(string(privPEM))
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	pt, err := dec.Decrypt(ct)
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	if !writeBytes(mod, outPtr, pt) {
		setLastError(errOOB)
		return errSentinel
	}
	return uint32(len(pt))
}

// rsa_generate_keypair(bits, priv_out, pub_out, pub_len_ptr) -> uint32
func hostRsaGenerateKeypair(_ context.Context, mod api.Module, bits, privOut, pubOut, pubLenPtr uint32) uint32 {
	kp, err := ocrypto.NewRSAKeyPair(int(bits))
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		setLastError(err)
		return errSentinel
	}
	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		setLastError(err)
		return errSentinel
	}

	privBytes := []byte(privPEM)
	pubBytes := []byte(pubPEM)

	if !writeBytes(mod, privOut, privBytes) {
		setLastError(errOOB)
		return errSentinel
	}
	if !writeBytes(mod, pubOut, pubBytes) {
		setLastError(errOOB)
		return errSentinel
	}
	// Write public key length as little-endian uint32.
	var pubLenLE [4]byte
	binary.LittleEndian.PutUint32(pubLenLE[:], uint32(len(pubBytes)))
	if !writeBytes(mod, pubLenPtr, pubLenLE[:]) {
		setLastError(errOOB)
		return errSentinel
	}
	return uint32(len(privBytes))
}

// get_last_error(out_ptr, out_capacity) -> uint32
func hostGetLastError(_ context.Context, mod api.Module, outPtr, outCapacity uint32) uint32 {
	msg := getAndClearLastError()
	if msg == "" {
		return 0
	}
	msgBytes := []byte(msg)
	if uint32(len(msgBytes)) > outCapacity {
		msgBytes = msgBytes[:outCapacity]
	}
	if !writeBytes(mod, outPtr, msgBytes) {
		return 0
	}
	return uint32(len(msgBytes))
}

// Sentinel errors for common host-side failures.
type hostErr string

func (e hostErr) Error() string { return string(e) }

const (
	errOOB    hostErr = "host: memory access out of bounds"
	errReadKey hostErr = "host: failed to read key from WASM memory"
	errReadCT  hostErr = "host: failed to read ciphertext from WASM memory"
)
