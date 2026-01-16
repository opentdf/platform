package trust

import (
	"context"
	"crypto/elliptic"

	"github.com/opentdf/platform/lib/ocrypto"
)

// Type aliases for backward compatibility - these interfaces are now defined in lib/ocrypto
type (
	// Deprecated: use ocrypto.Encapsulator
	Encapsulator = ocrypto.Encapsulator
	// Deprecated: use ocrypto.ProtectedKey
	ProtectedKey = ocrypto.ProtectedKey
)

// KeyManager combines key lookup functionality with cryptographic operations
type KeyManager interface {
	// Name is a unique identifier for the key manager.
	// This can be used by the KeyDetail.System() method to determine which KeyManager to use,
	// when multiple KeyManagers are installed.
	Name() string

	// Decrypt decrypts data that was encrypted with the key identified by keyID
	// For EC keys, ephemeralPublicKey must be non-nil
	// For RSA keys, ephemeralPublicKey should be nil
	// Returns an UnwrappedKeyData interface for further operations
	Decrypt(ctx context.Context, key KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (ProtectedKey, error)

	// DeriveKey computes an agreed upon secret key derived from an ECDH exchange.
	DeriveKey(ctx context.Context, key KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error)

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

// NamedKeyManagerFactory pairs a KeyManagerFactory with its intended registration name.
// Use NamedKeyManagerCtxFactory instead.
type NamedKeyManagerFactory struct {
	Name    string
	Factory KeyManagerFactory
}

// NamedKeyManagerCtxFactory pairs a KeyManagerFactoryCtx with its intended registration name.
type NamedKeyManagerCtxFactory struct {
	Name    string
	Factory KeyManagerFactoryCtx
}
