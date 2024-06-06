package security

import (
	"crypto"
	"crypto/elliptic"
)

type CryptoProvider interface {
	RSAPublicKey(keyID string) (string, error)
	RSAPublicKeyAsJSON(keyID string) (string, error)
	RSADecrypt(hash crypto.Hash, keyID string, keyLabel string, ciphertext []byte) ([]byte, error)

	ECPublicKey(keyID string) (string, error)
	ECCertificate(keyID string) (string, error)
	GenerateNanoTDFSymmetricKey(ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error)
	GenerateEphemeralKasKeys() (any, []byte, error)
	GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)
	Close()
}
