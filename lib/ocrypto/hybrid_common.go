package ocrypto

import (
	"crypto/sha256"
	"fmt"
)

// HybridWrapDEK parses the recipient's hybrid public key PEM via the
// OID-routed dispatcher, asserts the encryptor matches the requested ktype,
// and produces the ASN.1-encoded wrapped DEK envelope used in
// `hybrid-wrapped` manifests.
func HybridWrapDEK(ktype KeyType, kasPublicKeyPEM string, dek []byte) ([]byte, error) {
	enc, err := FromPublicPEM(kasPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("hybrid public key: %w", err)
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
