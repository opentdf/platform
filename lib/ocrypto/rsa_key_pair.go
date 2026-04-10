package ocrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

type RsaKeyPair struct {
	privateKey *rsa.PrivateKey
}

func FromRSA(k *rsa.PrivateKey) RsaKeyPair {
	return RsaKeyPair{k}
}

// NewRSAKeyPair Generates an RSA key pair of the given bit size.
func NewRSAKeyPair(bits int) (RsaKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKeyPair{}, fmt.Errorf("rsa.GenerateKe failed: %w", err)
	}

	rsaKeyPair := RsaKeyPair{privateKey: privateKey}
	return rsaKeyPair, nil
}

// PrivateKeyInPemFormat Returns private key in pem format.
func (keyPair RsaKeyPair) PrivateKeyInPemFormat() (string, error) {
	return privateKeyInPemFormat(keyPair.privateKey)
}

// PublicKeyInPemFormat Returns public key in pem format.
func (keyPair RsaKeyPair) PublicKeyInPemFormat() (string, error) {
	if keyPair.privateKey == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	return publicKeyInPemFormat(&keyPair.privateKey.PublicKey)
}

// KeySize Return the size of this rsa key pair.
func (keyPair RsaKeyPair) KeySize() (int, error) {
	if keyPair.privateKey == nil {
		return -1, errors.New("failed to return key size")
	}
	return keyPair.privateKey.N.BitLen(), nil
}

func (keyPair RsaKeyPair) Decrypt(data []byte) ([]byte, error) {
	return AsymDecryption{PrivateKey: keyPair.privateKey}.Decrypt(data)
}

func (keyPair RsaKeyPair) Public() (PublicKeyEncryptor, error) {
	if keyPair.privateKey == nil {
		return nil, errors.New("failed to generate public key encryptor, private key is empty")
	}

	return &AsymEncryption{PublicKey: &keyPair.privateKey.PublicKey}, nil
}

func (keyPair RsaKeyPair) KeyType() KeyType {
	if keyPair.privateKey == nil {
		return KeyType("rsa:[unknown]")
	}

	switch keyPair.privateKey.Size() {
	case RSA2048Size / 8: //nolint:mnd // standard key size in bytes
		return RSA2048Key
	case RSA4096Size / 8: //nolint:mnd // large key size in bytes
		return RSA4096Key
	default:
		return KeyType(fmt.Sprintf("rsa:%d", keyPair.privateKey.Size()*8)) //nolint:mnd // convert to bits
	}
}

func (keyPair RsaKeyPair) DeriveSharedKey(_ string) ([]byte, error) {
	return nil, errors.New("shared key derivation is unsupported for RSA private keys")
}

// GetKeyType returns the key type (RSAKey)
func (keyPair RsaKeyPair) GetKeyType() KeyType {
	return keyPair.KeyType()
}
