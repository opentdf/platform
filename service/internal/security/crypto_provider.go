package security

import (
	"crypto"
	"crypto/elliptic"
)

type KID string
type Algorithm string

const (
	// Key agreement along P-256
	AlgorithmECP256R1 = Algorithm("ec:secp256r1")
	// Used for encryption with RSA of the KAO
	AlgorithmRSA2048 = Algorithm("rsa:2048")
)

type CryptoProvider interface {
	// Gets some KID associated with a given algorithm.
	// Returns empty string if none are found.
	FindKID(alg Algorithm) (KID, error)
	RSAPublicKey(keyID KID) (string, error)
	RSAPublicKeyAsJSON(keyID KID) (string, error)
	RSADecrypt(hash crypto.Hash, keyID KID, keyLabel string, ciphertext []byte) ([]byte, error)

	ECPublicKey(keyID KID) (string, error)
	ECCertificate(keyID KID) (string, error)
	GenerateNanoTDFSymmetricKey(kasKID KID, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error)
	GenerateEphemeralKasKeys() (any, []byte, error)
	GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)
	Close()
}
