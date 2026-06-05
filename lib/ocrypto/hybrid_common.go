package ocrypto

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
)

// HybridWrapDEK parses the recipient's hybrid public key PEM, encapsulates
// against it using the scheme implied by ktype, and returns the ASN.1-encoded
// wrapped DEK envelope used in `hybrid-wrapped` manifests. It dispatches across
// both the X-Wing and NIST EC + ML-KEM families so SDK call sites do not need
// to repeat the algorithm switch.
//
// The HKDF salt is the default TDF salt; callers that need a non-default salt
// should call the per-scheme `*WrapDEK` helpers directly.
func HybridWrapDEK(ktype KeyType, kasPublicKeyPEM string, dek []byte) ([]byte, error) {
	switch ktype { //nolint:exhaustive // only handle hybrid types
	case HybridXWingKey:
		pubKey, err := XWingPubKeyFromPem([]byte(kasPublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("X-Wing public key: %w", err)
		}
		return XWingWrapDEK(pubKey, dek)
	case HybridSecp256r1MLKEM768Key:
		pubKey, err := P256MLKEM768PubKeyFromPem([]byte(kasPublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("P-256+ML-KEM-768 public key: %w", err)
		}
		return P256MLKEM768WrapDEK(pubKey, dek)
	case HybridSecp384r1MLKEM1024Key:
		pubKey, err := P384MLKEM1024PubKeyFromPem([]byte(kasPublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("P-384+ML-KEM-1024 public key: %w", err)
		}
		return P384MLKEM1024WrapDEK(pubKey, dek)
	default:
		return nil, fmt.Errorf("unsupported hybrid key type: %s", ktype)
	}
}

// defaultTDFSalt returns the salt used for HKDF derivation in all TDF hybrid
// key wrapping schemes (X-Wing and NIST EC + ML-KEM). Defined here rather than
// in a per-scheme file so that any change applies uniformly across schemes.
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

// cloneOrNil returns a copy of data, or nil if data is empty.
func cloneOrNil(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return append([]byte(nil), data...)
}
