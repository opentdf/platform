package security

import (
	"context"
	"crypto/elliptic"

	"github.com/opentdf/platform/lib/ocrypto"
)

// UnwrappedKeyData represents a decrypted key with operations that can be performed on it
type UnwrappedKeyData interface {
	// VerifyBinding checks if the policy binding matches the given policy data
	VerifyBinding(ctx context.Context, policy []byte) error

	// Export returns the raw key data, optionally encrypting it with the provided encryptor
	Export(encryptor ocrypto.PublicKeyEncryptor) ([]byte, error)
}

// SecurityProvider combines key lookup functionality with cryptographic operations
type SecurityProvider interface {
	// Embed KeyLookup interface for key management capabilities
	KeyLookup

	// Decrypt decrypts data that was encrypted with the key identified by keyID
	// For EC keys, ephemeralPublicKey must be non-nil
	// For RSA keys, ephemeralPublicKey should be nil
	// Returns an UnwrappedKeyData interface for further operations
	Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (UnwrappedKeyData, error)

	// GenerateNanoTDFSymmetricKey generates a symmetric key for NanoTDF
	GenerateNanoTDFSymmetricKey(ctx context.Context, kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error)

	// GenerateNanoTDFSessionKey generates a session key for NanoTDF
	GenerateNanoTDFSessionKey(ctx context.Context, ephemeralPublicKey string) (ocrypto.PublicKeyEncryptor, error)

	// Close releases any resources held by the provider
	Close()
}
