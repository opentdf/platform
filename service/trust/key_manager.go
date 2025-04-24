package trust

import (
	"context"
	"crypto/elliptic"
)

type Encapsulator interface {
	// Encrypt wraps a secret key with the encapsulation key
	Encrypt(data []byte) ([]byte, error)

	// PublicKeyInPemFormat Returns public key in pem format, or the empty string if not present
	PublicKeyInPemFormat() (string, error)

	// For EC schemes, this method returns the public part of the ephemeral key.
	// Otherwise, it returns nil.
	EphemeralKey() []byte
}

// ProtectedKey represents a decrypted key with operations that can be performed on it
type ProtectedKey interface {
	// VerifyBinding checks if the policy binding matches the given policy data
	VerifyBinding(ctx context.Context, policy, binding []byte) error

	// Export returns the raw key data, optionally encrypting it with the provided encryptor
	Export(encryptor Encapsulator) ([]byte, error)

	// Used to decrypt encrypted policies and metadata
	DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error)
}

// KeyManager combines key lookup functionality with cryptographic operations
type KeyManager interface {
	// Name is a unique identifier for the key manager.
	// This can be used by the KeyDetail.Mode() method to determine which KeyManager to use,
	// when multiple KeyManagers are installed.
	Name() string

	// Decrypt decrypts data that was encrypted with the key identified by keyID
	// For EC keys, ephemeralPublicKey must be non-nil
	// For RSA keys, ephemeralPublicKey should be nil
	// Returns an UnwrappedKeyData interface for further operations
	Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (ProtectedKey, error)

	// DeriveKey computes an agreed upon secret key, which NanoTDF may directly as the DEK or a key split
	DeriveKey(ctx context.Context, kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error)

	// GenerateECSessionKey generates a private session key, for use with a client-provided ephemeral public key
	GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (Encapsulator, error)

	// Close releases any resources held by the provider
	Close()
}

// Helper interface for unified key management objects
type KeyService interface {
	KeyIndex
	KeyManager
}
