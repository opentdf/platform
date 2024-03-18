package crypto

import (
	"context"
	"crypto"
)

type CryptoOperations interface {
	DecryptOAEP(key string, ciphertext []byte, hashFunction crypto.Hash, label []byte) ([]byte, error)
	EncryptWithPublicKey(data []byte, pub string) ([]byte, error)
	GetPublicKey(keyId string) (string, error)
	GetPrivateKey(keyId string) (string, error)
	GenerateHMACDigest(ctx context.Context, msg, key []byte) ([]byte, error)
}
