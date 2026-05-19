package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// MLKEM768CiphertextSize is the byte length of an ML-KEM-768 ciphertext.
	MLKEM768CiphertextSize = 1088
)

// MLKEMKeyPair holds an ML-KEM-768 decapsulation (private) key.
// The public encapsulation key is derived from the private key.
type MLKEMKeyPair struct {
	dk *mlkem.DecapsulationKey768
}

// NewMLKEMKeyPair generates a fresh ML-KEM-768 key pair.
func NewMLKEMKeyPair() (MLKEMKeyPair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return MLKEMKeyPair{}, fmt.Errorf("mlkem.GenerateKey768 failed: %w", err)
	}
	return MLKEMKeyPair{dk: dk}, nil
}

// IsMLKEMKeyType reports whether the given KeyType is an ML-KEM type.
func IsMLKEMKeyType(kt KeyType) bool {
	return kt == MLKEM768Key
}

// GetKeyType implements KeyPair.
func (kp MLKEMKeyPair) GetKeyType() KeyType {
	return MLKEM768Key
}

// PublicKeyInPemFormat returns the ML-KEM-768 encapsulation key in PEM format.
func (kp MLKEMKeyPair) PublicKeyInPemFormat() (string, error) {
	if kp.dk == nil {
		return "", errors.New("nil ML-KEM-768 key")
	}
	b := kp.dk.EncapsulationKey().Bytes()
	block := &pem.Block{
		Type:  "ML-KEM-768 PUBLIC KEY",
		Bytes: b,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// PrivateKeyInPemFormat returns the ML-KEM-768 seed (private key) in PEM format.
func (kp MLKEMKeyPair) PrivateKeyInPemFormat() (string, error) {
	if kp.dk == nil {
		return "", errors.New("nil ML-KEM-768 key")
	}
	block := &pem.Block{
		Type:  "ML-KEM-768 PRIVATE KEY",
		Bytes: kp.dk.Bytes(),
	}
	return string(pem.EncodeToMemory(block)), nil
}

// MLKEMDecapsulateAndUnwrap recovers the DEK from an ML-KEM-768 wrapped key blob.
//
// wrappedKey layout (after base64 decoding by the caller):
//
//	[0 : 1088]  ML-KEM-768 ciphertext
//	[1088 : ]   AES-256-GCM encrypted DEK (12-byte nonce prepended)
//
// The AES wrapping key is: HKDF-SHA256(shared_secret, salt=TDF-salt).
func MLKEMDecapsulateAndUnwrap(privateKeyPEM []byte, wrappedKey []byte) ([]byte, error) {
	if len(wrappedKey) <= MLKEM768CiphertextSize {
		return nil, fmt.Errorf("mlkem wrapped key too short: %d bytes", len(wrappedKey))
	}

	dk, err := mlkemDecapsKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	ct := wrappedKey[:MLKEM768CiphertextSize]
	encDEK := wrappedKey[MLKEM768CiphertextSize:]

	sharedSecret, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("mlkem decapsulate failed: %w", err)
	}

	wk, err := deriveMLKEMWrappingKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	return aesGCMDecrypt(wk, encDEK)
}

// mlkemDecapsKeyFromPEM parses a PEM-encoded ML-KEM-768 private key (seed).
func mlkemDecapsKeyFromPEM(privateKeyPEM []byte) (*mlkem.DecapsulationKey768, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse ML-KEM-768 PEM private key")
	}
	dk, err := mlkem.NewDecapsulationKey768(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
	}
	return dk, nil
}

// deriveMLKEMWrappingKey derives a 32-byte AES key from the ML-KEM shared secret
// using HKDF-SHA256 with the standard TDF salt.
func deriveMLKEMWrappingKey(sharedSecret []byte) ([]byte, error) {
	salt := mlkemTDFSalt()
	h := hkdf.New(sha256.New, sharedSecret, salt, nil)
	key := make([]byte, 32) //nolint:mnd // AES-256
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("hkdf derivation failed: %w", err)
	}
	return key, nil
}

// mlkemTDFSalt returns the SHA-256("TDF") salt used for HKDF in ML-KEM key wrapping.
func mlkemTDFSalt() []byte {
	h := sha256.New()
	h.Write([]byte("TDF"))
	return h.Sum(nil)
}

// aesGCMDecrypt decrypts AES-256-GCM ciphertext of the form: [12-byte nonce | ciphertext+tag].
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short for nonce")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm open failed: %w", err)
	}
	return plaintext, nil
}

// MLKEMEncapsulateAndWrap encapsulates a DEK for the given ML-KEM-768 public key PEM.
// Returns wrappedKey = ciphertext || AES-GCM(wk, dek).
// This is the counterpart used by SDK implementations; provided here for testing.
func MLKEMEncapsulateAndWrap(publicKeyPEM []byte, dek []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse ML-KEM-768 PEM public key")
	}
	ek, err := mlkem.NewEncapsulationKey768(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mlkem.NewEncapsulationKey768 failed: %w", err)
	}

	sharedSecret, ct := ek.Encapsulate()

	wk, err := deriveMLKEMWrappingKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	encDEK, err := aesGCMEncrypt(wk, dek)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, MLKEM768CiphertextSize+len(encDEK))
	result = append(result, ct...)
	result = append(result, encDEK...)
	return result, nil
}

// aesGCMEncrypt encrypts plaintext using AES-256-GCM, prepending a random 12-byte nonce.
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
