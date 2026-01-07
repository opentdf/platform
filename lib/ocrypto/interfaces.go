package ocrypto

import (
	"context"
)

// Encapsulator enables key encapsulation with a public key
type Encapsulator interface {
	// Encapsulate wraps a secret key with the encapsulation key
	Encapsulate(dek ProtectedKey) ([]byte, error)

	// Encrypt wraps a secret key with the encapsulation key
	Encrypt(data []byte) ([]byte, error)

	// PublicKeyAsPEM exports the public key, used to encapsulate the value, in Privacy-Enhanced Mail format,
	// or the empty string if not present.
	PublicKeyAsPEM() (string, error)

	// For EC schemes, this method returns the public part of the ephemeral key.
	// Otherwise, it returns nil.
	EphemeralKey() []byte
}

// ProtectedKey represents a decrypted key with operations that can be performed on it
type ProtectedKey interface {
	// VerifyBinding checks if the policy binding matches the given policy data
	VerifyBinding(ctx context.Context, policy, policyBinding []byte) error

	// Export returns the raw key data, optionally encrypting it with the provided encapsulator
	//
	// Deprecated: Use the Encapsulator's Encapsulate method instead.
	Export(encapsulator Encapsulator) ([]byte, error)

	// DecryptAESGCM decrypts encrypted policies and metadata
	DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error)
}
