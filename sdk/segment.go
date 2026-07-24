package sdk

import (
	"crypto/rand"
	"io"

	"github.com/opentdf/platform/lib/ocrypto"
)

// defaultRand is the production entropy source used by the chunked
// writer when no other io.Reader is injected.
var defaultRand io.Reader = rand.Reader

// SegmentCipher encrypts a single payload segment. Implementations
// must be safe for concurrent use by segment writers.
type SegmentCipher interface {
	// EncryptInPlace returns (ciphertext, nonce, error).
	EncryptInPlace(data []byte) ([]byte, []byte, error)
}

// SegmentCipherFactory builds a SegmentCipher from the
// writer-generated DEK. Tests inject deterministic ciphers for
// reproducible fixtures.
type SegmentCipherFactory func(dek []byte) (SegmentCipher, error)

// DefaultSegmentCipherFactory wraps ocrypto.NewAESGcm (AES-256-GCM).
func DefaultSegmentCipherFactory(dek []byte) (SegmentCipher, error) {
	return ocrypto.NewAESGcm(dek)
}
