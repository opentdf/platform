package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type GcmEncryption struct {
	block     cipher.Block
	nonceSize int
}

// CreateGcmEncryption creates and returns a new GcmEncryption.
func CreateGcmEncryption(key []byte, nonceSize int) (GcmEncryption, error) {
	if len(key) == 0 {
		return GcmEncryption{}, errors.New("invalid key size for gcm encryption")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return GcmEncryption{}, err
	}

	return GcmEncryption{block: block, nonceSize: nonceSize}, nil
}

// Encrypt encrypts data with symmetric key.
// NOTE: This method adds IV as preamble to encrypted data.
func (gcmEncryption GcmEncryption) Encrypt(data []byte) (out []byte, err error) {
	nonce, err := RandomBytes(gcmEncryption.nonceSize)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCMWithNonceSize(gcmEncryption.block, gcmEncryption.nonceSize)
	if err != nil {
		return nil, err
	}

	cipherText := aesGcm.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

// EncryptWithIV encrypts data with symmetric key.
// NOTE: This method adds IV as preamble to encrypted data.
func (gcmEncryption GcmEncryption) EncryptWithIV(iv, in []byte) (out []byte, err error) {
	aesGcm, err := cipher.NewGCMWithNonceSize(gcmEncryption.block, len(iv))
	if err != nil {
		return nil, err
	}

	cipherText := aesGcm.Seal(iv, iv, in, nil)
	return cipherText, nil
}
