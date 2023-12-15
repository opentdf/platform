package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type GcmDecryption struct {
	block     cipher.Block
	nonceSize int
}

// CreateGcmDecryption creates and returns a new GcmDecryption.
func CreateGcmDecryption(key []byte, nonceSize int) (GcmDecryption, error) {
	if len(key) == 0 {
		return GcmDecryption{}, errors.New("invalid key size for gcm decryption")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return GcmDecryption{}, err
	}

	return GcmDecryption{block: block, nonceSize: nonceSize}, nil
}

// Decrypt decrypts data with symmetric key.
// NOTE: This method expects IV as preamble of data.
func (gcmDecryption GcmDecryption) Decrypt(data []byte) (out []byte, err error) {

	// extract nonce and cipherText
	nonce, cipherText := data[:gcmDecryption.nonceSize], data[gcmDecryption.nonceSize:]

	aesGcm, err := cipher.NewGCMWithNonceSize(gcmDecryption.block, gcmDecryption.nonceSize)
	if err != nil {
		return nil, err
	}

	plainData, err := aesGcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainData, nil
}

// DecryptWithIV decrypts data with symmetric key.
func (gcmDecryption GcmDecryption) DecryptWithIV(iv, in []byte) (out []byte, err error) {

	aesGcm, err := cipher.NewGCMWithNonceSize(gcmDecryption.block, len(iv))
	if err != nil {
		return nil, err
	}

	plainData, err := aesGcm.Open(nil, iv, in, nil)
	if err != nil {
		return nil, err
	}

	return plainData, nil
}
