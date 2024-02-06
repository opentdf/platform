package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

type AesGcm struct {
	block cipher.Block
}

// DefaultNonceSize The default nonce size for the TDF3 encryption.
const DefaultNonceSize = 16

const GcmStandardNonceSize = 12

// NewAESGcm creates and returns a new AesGcm.
func NewAESGcm(key []byte) (AesGcm, error) {
	if len(key) == 0 {
		return AesGcm{}, errors.New("invalid key size for gcm encryption")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return AesGcm{}, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	return AesGcm{block: block}, nil
}

// Encrypt encrypts data with symmetric key.
// NOTE: This method use nonce of 12 bytes and auth tag as aes block size(16 bytes).
func (aesGcm AesGcm) Encrypt(data []byte) ([]byte, error) {
	nonce, err := RandomBytes(GcmStandardNonceSize)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(aesGcm.block, GcmStandardNonceSize)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithNonceSize failed: %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

// EncryptWithIV encrypts data with symmetric key.
// NOTE: This method use default auth tag as aes block size(16 bytes)
// and expects iv of 16 bytes.
func (aesGcm AesGcm) EncryptWithIV(iv, data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCMWithNonceSize(aesGcm.block, len(iv))
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithNonceSize failed: %w", err)
	}

	cipherText := gcm.Seal(iv, iv, data, nil)
	return cipherText, nil
}

// EncryptWithIVAndTagSize encrypts data with symmetric key.
// NOTE: This method expects gcm standard nonce size(12) of iv.
func (aesGcm AesGcm) EncryptWithIVAndTagSize(iv, data []byte, authTagSize int) ([]byte, error) {
	if len(iv) != GcmStandardNonceSize {
		return nil, errors.New("invalid nonce size, expects GcmStandardNonceSize")
	}

	gcm, err := cipher.NewGCMWithTagSize(aesGcm.block, authTagSize)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithTagSize failed: %w", err)
	}

	cipherText := gcm.Seal(iv, iv, data, nil)
	return cipherText, nil
}

// Decrypt decrypts data with symmetric key.
// NOTE: This method use nonce of 12 bytes and auth tag as aes block size(16 bytes)
// also expects IV as preamble of data.
func (aesGcm AesGcm) Decrypt(data []byte) ([]byte, error) { // extract nonce and cipherText
	nonce, cipherText := data[:GcmStandardNonceSize], data[GcmStandardNonceSize:]

	gcm, err := cipher.NewGCMWithNonceSize(aesGcm.block, GcmStandardNonceSize)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithNonceSize failed: %w", err)
	}

	plainData, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open failed: %w", err)
	}

	return plainData, nil
}

// DecryptWithTagSize decrypts data with symmetric key.
// NOTE: This method expects gcm standard nonce size(12) of iv.
func (aesGcm AesGcm) DecryptWithTagSize(data []byte, authTagSize int) ([]byte, error) {
	// extract nonce and cipherText
	nonce, cipherText := data[:GcmStandardNonceSize], data[GcmStandardNonceSize:]

	gcm, err := cipher.NewGCMWithTagSize(aesGcm.block, authTagSize)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithTagSize failed: %w", err)
	}

	plainData, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open failed: %w", err)
	}

	return plainData, nil
}
