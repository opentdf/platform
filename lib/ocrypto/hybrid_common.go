package ocrypto

import (
	"crypto/sha256"
	"fmt"
)

// WrapDEK parses the recipient's KEM public key PEM via the OID/PEM-routed
// dispatcher and produces the ASN.1-encoded wrapped DEK envelope. It covers
// both pure ML-KEM (`mlkem-wrapped`) and hybrid PQ/T (`hybrid-wrapped`) KAOs so
// SDK and service callers can wrap against any KEM scheme without a per-scheme
// switch — the encryptor returned by FromPublicPEM selects the format.
func WrapDEK(ktype KeyType, kasPublicKeyPEM string, dek []byte) ([]byte, error) {
	if !IsKEMKeyType(ktype) {
		return nil, fmt.Errorf("unsupported KEM key type: %s", ktype)
	}

	enc, err := FromPublicPEM(kasPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("kem public key: %w", err)
	}
	if enc.KeyType() != ktype {
		return nil, fmt.Errorf("kem key type mismatch: PEM is %s, requested %s", enc.KeyType(), ktype)
	}
	return enc.Encrypt(dek)
}

// HybridWrapDEK parses the recipient's hybrid public key PEM via the
// OID-routed dispatcher, asserts the encryptor matches the requested ktype,
// and produces the ASN.1-encoded wrapped DEK envelope used in
// `hybrid-wrapped` manifests.
func HybridWrapDEK(ktype KeyType, kasPublicKeyPEM string, dek []byte) ([]byte, error) {
	if !IsHybridKeyType(ktype) {
		return nil, fmt.Errorf("unsupported hybrid key type: %s", ktype)
	}

	enc, err := FromPublicPEM(kasPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("hybrid public key: %w", err)
	}
	if enc.Type() != Hybrid {
		return nil, fmt.Errorf("public key is not a hybrid scheme: %s", enc.KeyType())
	}
	if enc.KeyType() != ktype {
		return nil, fmt.Errorf("hybrid key type mismatch: PEM is %s, requested %s", enc.KeyType(), ktype)
	}
	return enc.Encrypt(dek)
}

// defaultTDFSalt returns the salt used for HKDF derivation in the X-Wing
// hybrid wrapping scheme. The NIST composite-KEM hybrids derive their wrap
// key without salt per draft-ietf-lamps-pq-composite-kem-14 §3.4 (combiner).
func defaultTDFSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	return digest.Sum(nil)
}

// cloneOrNil returns a copy of data, or nil if data is empty.
func cloneOrNil(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return append([]byte(nil), data...)
}
