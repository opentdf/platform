package security

import (
	"crypto"
	"crypto/elliptic"
)

const (
	// AlgorithmECP256R1 Key agreement along P-256
	AlgorithmECP256R1 = "ec:secp256r1"
	// AlgorithmECP384R1 Key agreement along P-384
	AlgorithmECP384R1 = "ec:secp384r1"
	// AlgorithmECP512R1 Key agreement along P-512
	AlgorithmECP512R1 = "ec:secp512r1"
	// AlgorithmECP512R1 Used for encryption with RSA of the KAO
	AlgorithmRSA2048 = "rsa:2048"
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
	GenerateEphemeralKasKeys(curve elliptic.Curve) (any, []byte, error)
	GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)
	Close()
}
