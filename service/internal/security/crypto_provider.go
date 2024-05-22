package security

import "crypto"

type CryptoProvider interface {
	RSAPublicKey(keyID string) (string, error)
	RSAPublicKeyAsJSON(keyID string) (string, error)
	RSADecrypt(hash crypto.Hash, keyID string, keyLabel string, ciphertext []byte) ([]byte, error)

	ECPublicKey(keyID string) (string, error)
	GenerateNanoTDFSymmetricKey(ephemeralPublicKeyBytes []byte) ([]byte, error)
	GenerateEphemeralKasKeys() (any, []byte, error)
	GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error)
	Close()
}
