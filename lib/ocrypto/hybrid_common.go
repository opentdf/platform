package ocrypto

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
)

// WrapDEK parses the recipient's KEM public key PEM, encapsulates against it
// using the scheme implied by ktype, and returns the ASN.1-encoded wrapped DEK
// envelope used in `hybrid-wrapped` and `mlkem-wrapped` manifests. It covers
// every KEM family — pure ML-KEM, X-Wing, and the NIST EC + ML-KEM hybrids —
// so SDK call sites do not need to repeat the algorithm switch.
//
// For hybrid PQ/T schemes the HKDF salt is the default TDF salt; callers that
// need a non-default salt should construct an encryptor via
// FromPublicPEMWithSalt instead. Pure ML-KEM ignores salt/info and uses the
// 32-byte Decaps shared secret directly as the AES-GCM wrap key — see
// adr/decisions/2026-06-16-mlkem-direct-key-wrap.md.
func WrapDEK(ktype KeyType, kasPublicKeyPEM string, dek []byte) ([]byte, error) {
	if !IsKEMKeyType(ktype) {
		return nil, fmt.Errorf("unsupported KEM key type: %s", ktype)
	}
	enc, err := FromPublicPEM(kasPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse %s public key: %w", ktype, err)
	}
	if got := enc.KeyType(); got != ktype {
		return nil, fmt.Errorf("KEM key type mismatch: want %s, got %s", ktype, got)
	}
	return enc.Encrypt(dek)
}

// HybridWrapDEK is the legacy entrypoint for hybrid PQ/T wrapping. It now
// delegates to WrapDEK, which covers both hybrid and pure ML-KEM schemes.
//
// Deprecated: Use WrapDEK.
func HybridWrapDEK(ktype KeyType, kasPublicKeyPEM string, dek []byte) ([]byte, error) {
	return WrapDEK(ktype, kasPublicKeyPEM, dek)
}

// defaultTDFSalt returns the salt used for HKDF derivation in all TDF KEM key
// wrapping schemes (pure ML-KEM, X-Wing, and NIST EC + ML-KEM). Defined here
// rather than in a per-scheme file so any change applies uniformly.
func defaultTDFSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	return digest.Sum(nil)
}

// rawToPEM wraps a fixed-size byte slice in a PEM block of the given type. Used
// by both X-Wing and NIST hybrid key serialization.
func rawToPEM(blockType string, raw []byte, expectedSize int) (string, error) {
	if len(raw) != expectedSize {
		return "", fmt.Errorf("invalid %s size: got %d want %d", blockType, len(raw), expectedSize)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: raw,
	})
	if pemBytes == nil {
		return "", fmt.Errorf("failed to encode %s to PEM", blockType)
	}

	return string(pemBytes), nil
}

// decodeSizedPEMBlock decodes a PEM block of the given type and verifies its
// payload is exactly expectedSize bytes long. Used by X-Wing and NIST hybrid
// PEM helpers that carry raw-bytes PEM blobs (pre-SPKI-migration).
func decodeSizedPEMBlock(data []byte, blockType string, expectedSize int) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM formatted %s", blockType)
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("unexpected PEM block type: got %s want %s", block.Type, blockType)
	}
	if len(block.Bytes) != expectedSize {
		return nil, fmt.Errorf("invalid %s size: got %d want %d", blockType, len(block.Bytes), expectedSize)
	}

	return append([]byte(nil), block.Bytes...), nil
}

// cloneOrNil returns a copy of data, or nil if data is empty.
func cloneOrNil(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return append([]byte(nil), data...)
}
