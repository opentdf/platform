package ocrypto

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

// ErrUnsupportedAESGCMConfiguration is returned for AES-GCM options that Go strict FIPS mode does not allow.
var ErrUnsupportedAESGCMConfiguration = errors.New("unsupported AES-GCM configuration")

// NewAESGcm creates and returns a new AesGcm.
func NewAESGcm(key []byte) (AesGcm, error) {
	if len(key) == 0 {
		return AesGcm{}, ErrInvalidKeyData
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return AesGcm{}, fmt.Errorf("%w: %w", ErrInvalidKeyData, err)
	}

	return AesGcm{block: block}, nil
}

// Encrypt encrypts data with symmetric key.
// NOTE: This method use nonce of 12 bytes and auth tag as aes block size(16 bytes).
func (aesGcm AesGcm) Encrypt(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCMWithRandomNonce(aesGcm.block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithRandomNonce failed: %w", err)
	}

	cipherText := gcm.Seal(nil, nil, data, nil)
	return cipherText, nil
}

func (aesGcm AesGcm) EncryptInPlace(data []byte) ([]byte, []byte, error) {
	gcm, err := cipher.NewGCMWithRandomNonce(aesGcm.block)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewGCMWithRandomNonce failed: %w", err)
	}

	sealed := gcm.Seal(data[:0], nil, data, nil)
	nonce, cipherText := sealed[:GcmStandardNonceSize], sealed[GcmStandardNonceSize:]
	return cipherText, nonce, nil
}

// EncryptWithIV is unsupported because strict FIPS mode requires internally generated AES-GCM nonces.
func (AesGcm) EncryptWithIV(_, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("caller-managed IV encryption is not supported: %w", ErrUnsupportedAESGCMConfiguration)
}

// EncryptWithIVAndTagSize is unsupported because strict FIPS mode requires internally generated AES-GCM nonces.
func (AesGcm) EncryptWithIVAndTagSize(_, _ []byte, authTagSize int) ([]byte, error) {
	return nil, fmt.Errorf("caller-managed IV encryption with tag size %d is not supported: %w", authTagSize, ErrUnsupportedAESGCMConfiguration)
}

// Decrypt decrypts data with a 12-byte nonce prefix and a 16-byte AES-GCM authentication tag.
func (aesGcm AesGcm) Decrypt(data []byte) ([]byte, error) {
	if len(data) < GcmStandardNonceSize {
		return nil, ErrInvalidCiphertext
	}
	gcm, err := cipher.NewGCMWithRandomNonce(aesGcm.block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithRandomNonce failed: %w", err)
	}

	plainData, err := gcm.Open(nil, nil, data, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open failed: %w", err)
	}

	return plainData, nil
}

// DecryptWithTagSize decrypts data when authTagSize is the standard 16-byte AES-GCM tag size.
func (aesGcm AesGcm) DecryptWithTagSize(data []byte, authTagSize int) ([]byte, error) {
	if authTagSize != aes.BlockSize {
		return nil, fmt.Errorf("AES-GCM tag size %d is not supported: %w", authTagSize, ErrUnsupportedAESGCMConfiguration)
	}

	if len(data) < GcmStandardNonceSize {
		return nil, ErrInvalidCiphertext
	}

	return aesGcm.Decrypt(data)
}

// DecryptWithIVAndTagSize decrypts split IV and ciphertext when authTagSize is the standard 16-byte AES-GCM tag size.
func (aesGcm AesGcm) DecryptWithIVAndTagSize(iv, data []byte, authTagSize int) ([]byte, error) {
	if len(iv) != GcmStandardNonceSize {
		return nil, ErrInvalidCiphertext
	}

	if authTagSize != aes.BlockSize {
		return nil, fmt.Errorf("AES-GCM tag size %d is not supported: %w", authTagSize, ErrUnsupportedAESGCMConfiguration)
	}

	sealed := make([]byte, 0, len(iv)+len(data))
	sealed = append(sealed, iv...)
	sealed = append(sealed, data...)
	return aesGcm.Decrypt(sealed)
}
