package security

import (
	"context"
	"crypto/elliptic"
)

// SecurityProvider combines key lookup functionality with cryptographic operations
type SecurityProvider interface {
	// Embed KeyLookup interface for key management capabilities
	KeyLookup

	// Decrypt decrypts data that was encrypted with the key identified by keyID
	// For EC keys, ephemeralPublicKey must be non-nil
	// For RSA keys, ephemeralPublicKey should be nil
	Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) ([]byte, error)

	// GenerateNanoTDFSymmetricKey generates a symmetric key for NanoTDF
	GenerateNanoTDFSymmetricKey(ctx context.Context, kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error)

	// GenerateEphemeralKasKeys generates ephemeral keys for KAS operations
	GenerateEphemeralKasKeys(ctx context.Context) (any, []byte, error)

	// GenerateNanoTDFSessionKey generates a session key for NanoTDF
	GenerateNanoTDFSessionKey(ctx context.Context, privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)

	// Close releases any resources held by the provider
	Close()
}
