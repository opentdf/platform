package security

import (
	"crypto/elliptic"
)

// SecurityProvider combines key lookup functionality with cryptographic operations
type SecurityProvider interface {
	// Embed KeyLookup interface for key management capabilities
	KeyLookup

	// RSADecrypt decrypts RSA encrypted data
	RSADecrypt(keyID KeyIdentifier, ciphertext []byte) ([]byte, error)

	// ECDecrypt decrypts data encrypted with an EC key
	ECDecrypt(keyID KeyIdentifier, ephemeralPublicKey, ciphertext []byte) ([]byte, error)

	// GenerateNanoTDFSymmetricKey generates a symmetric key for NanoTDF
	GenerateNanoTDFSymmetricKey(kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error)

	// GenerateEphemeralKasKeys generates ephemeral keys for KAS operations
	GenerateEphemeralKasKeys() (any, []byte, error)

	// GenerateNanoTDFSessionKey generates a session key for NanoTDF
	GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)

	// Close releases any resources held by the provider
	Close()
}
