package security

import (
	"crypto"
	"crypto/elliptic"

	"github.com/opentdf/platform/protocol/go/policy"
)

type Algorithm string
type KeyFormat string
type KeyIdentifier string

const (
	// Key agreement along P-256
	AlgorithmECP256R1 Algorithm = "ec:secp256r1"
	// Used for encryption with RSA of the KAO
	AlgorithmRSA2048 Algorithm = "rsa:2048"

	FormatJWK = "jwk"
	FormatJWKSet = "jwks"

	FormatJWKSet = "jwks"
)

type CryptoProvider interface {
	// Gets some KID associated with a given algorithm.
	// Returns empty string if none are found.
	FindKID(alg string) string
	RSAPublicKey(keyID string) (string, error)
	RSAPublicKeyAsJSON(keyID string) (string, error)
	RSADecrypt(hash crypto.Hash, keyID string, keyLabel string, ciphertext []byte) ([]byte, error)

	ECPublicKey(keyID string) (string, error)
	ECCertificate(keyID string) (string, error)
	GenerateNanoTDFSymmetricKey(kasKID string, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error)
	GenerateEphemeralKasKeys() (any, []byte, error)
	GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)
	Close()

	// Given an optional algorithm and key identifier, return a set of all public
	// keys that have either match the given algorithm or identifier or both.
	// otherwise, returns all 'current' (recommended for use currently) keys.
	PublicKeySet(a Algorithm, k KeyIdentifier) policy.JWKSet
}
