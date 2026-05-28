package ocrypto

import (
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	MLKEM768PublicKeySize   = 1184 // mlkem768 encapsulation key
	MLKEM768PrivateKeySize  = 64   // mlkem768 seed (d || z)
	MLKEM768CiphertextSize  = 1088 // mlkem768 ciphertext
	MLKEM1024PublicKeySize  = 1568 // mlkem1024 encapsulation key
	MLKEM1024PrivateKeySize = 64   // mlkem1024 seed (d || z)
	MLKEM1024CiphertextSize = 1568 // mlkem1024 ciphertext

	mlkemWrapKeySize = 32 // AES-256 key size for wrap key derivation
)

type MLKEMWrappedKey struct {
	MLKEMCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK    []byte `asn1:"tag:1"`
}

type MLKEMEncryptor768 struct {
	publicKey []byte
	salt      []byte
	info      []byte
}

type MLKEMDecryptor768 struct {
	privateKey []byte
	salt       []byte
	info       []byte
}

type MLKEMEncryptor1024 struct {
	publicKey []byte
	salt      []byte
	info      []byte
}

type MLKEMDecryptor1024 struct {
	privateKey []byte
	salt       []byte
	info       []byte
}

func NewMLKEM768Encryptor(publicKey, salt, info []byte) (*MLKEMEncryptor768, error) {
	if len(publicKey) != MLKEM768PublicKeySize {
		return nil, fmt.Errorf("invalid ML-KEM-768 public key size: got %d want %d", len(publicKey), MLKEM768PublicKeySize)
	}

	return &MLKEMEncryptor768{
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
	}, nil
}

func (e *MLKEMEncryptor768) Encrypt(data []byte) ([]byte, error) {
	return mlkem768WrapDEK(e.publicKey, data, e.salt, e.info)
}

func (e *MLKEMEncryptor768) PublicKeyInPemFormat() (string, error) {
	pemBlock := &pem.Block{
		Type:  "MLKEM ENCAPSULATOR",
		Bytes: e.publicKey,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

func (e *MLKEMEncryptor768) Type() SchemeType {
	return MLKEM
}

func (e *MLKEMEncryptor768) KeyType() KeyType {
	return MLKEM768Key
}

func (e *MLKEMEncryptor768) EphemeralKey() []byte {
	return nil
}

func (e *MLKEMEncryptor768) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func NewMLKEM768Decryptor(privateKey []byte) (*MLKEMDecryptor768, error) {
	return NewSaltedMLKEM768Decryptor(privateKey, defaultTDFSalt(), nil)
}

func NewSaltedMLKEM768Decryptor(privateKey, salt, info []byte) (*MLKEMDecryptor768, error) {
	if len(privateKey) != MLKEM768PrivateKeySize {
		return nil, fmt.Errorf("invalid ML-KEM-768 private key size: got %d want %d", len(privateKey), MLKEM768PrivateKeySize)
	}

	return &MLKEMDecryptor768{
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
	}, nil
}

func (d *MLKEMDecryptor768) Decrypt(data []byte) ([]byte, error) {
	return mlkem768UnwrapDEK(d.privateKey, data, d.salt, d.info)
}

func (d *MLKEMDecryptor768) DecryptWithEphemeralKey(data, ephemeral []byte) ([]byte, error) {
	if len(ephemeral) > 0 {
		return nil, errors.New("ephemeral key should not be provided for ML-KEM-768 decryption")
	}
	return d.Decrypt(data)
}

func NewMLKEM1024Encryptor(publicKey, salt, info []byte) (*MLKEMEncryptor1024, error) {
	if len(publicKey) != MLKEM1024PublicKeySize {
		return nil, fmt.Errorf("invalid ML-KEM-1024 public key size: got %d want %d", len(publicKey), MLKEM1024PublicKeySize)
	}

	return &MLKEMEncryptor1024{
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
	}, nil
}

func (e *MLKEMEncryptor1024) Encrypt(data []byte) ([]byte, error) {
	return mlkem1024WrapDEK(e.publicKey, data, e.salt, e.info)
}

func (e *MLKEMEncryptor1024) PublicKeyInPemFormat() (string, error) {
	pemBlock := &pem.Block{
		Type:  "MLKEM ENCAPSULATOR",
		Bytes: e.publicKey,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

func (e *MLKEMEncryptor1024) Type() SchemeType {
	return MLKEM
}

func (e *MLKEMEncryptor1024) KeyType() KeyType {
	return MLKEM1024Key
}

func (e *MLKEMEncryptor1024) EphemeralKey() []byte {
	return nil
}

func (e *MLKEMEncryptor1024) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func NewMLKEM1024Decryptor(privateKey []byte) (*MLKEMDecryptor1024, error) {
	return NewSaltedMLKEM1024Decryptor(privateKey, defaultTDFSalt(), nil)
}

func NewSaltedMLKEM1024Decryptor(privateKey, salt, info []byte) (*MLKEMDecryptor1024, error) {
	if len(privateKey) != MLKEM1024PrivateKeySize {
		return nil, fmt.Errorf("invalid ML-KEM-1024 private key size: got %d want %d", len(privateKey), MLKEM1024PrivateKeySize)
	}

	return &MLKEMDecryptor1024{
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
	}, nil
}

func (d *MLKEMDecryptor1024) Decrypt(data []byte) ([]byte, error) {
	return mlkem1024UnwrapDEK(d.privateKey, data, d.salt, d.info)
}

func (d *MLKEMDecryptor1024) DecryptWithEphemeralKey(data, ephemeral []byte) ([]byte, error) {
	if len(ephemeral) > 0 {
		return nil, errors.New("ephemeral key should not be provided for ML-KEM-1024 decryption")
	}
	return d.Decrypt(data)
}

func MLKEM768WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return mlkem768WrapDEK(publicKeyRaw, dek, defaultTDFSalt(), nil)
}

func MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return mlkem768UnwrapDEK(privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

func MLKEM1024WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return mlkem1024WrapDEK(publicKeyRaw, dek, defaultTDFSalt(), nil)
}

func MLKEM1024UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return mlkem1024UnwrapDEK(privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

// MLKEM768Encapsulate performs ML-KEM-768 encapsulation, returning the shared
// secret and ciphertext without applying KDF or encryption.
func MLKEM768Encapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	if len(publicKeyRaw) != MLKEM768PublicKeySize {
		return nil, nil, fmt.Errorf("invalid ML-KEM-768 public key size: got %d want %d", len(publicKeyRaw), MLKEM768PublicKeySize)
	}

	ek, err := mlkem.NewEncapsulationKey768(publicKeyRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem.NewEncapsulationKey768 failed: %w", err)
	}

	sharedSecret, ciphertext := ek.Encapsulate()

	return sharedSecret, ciphertext, nil
}

// MLKEM1024Encapsulate performs ML-KEM-1024 encapsulation, returning the shared
// secret and ciphertext without applying KDF or encryption.
func MLKEM1024Encapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	if len(publicKeyRaw) != MLKEM1024PublicKeySize {
		return nil, nil, fmt.Errorf("invalid ML-KEM-1024 public key size: got %d want %d", len(publicKeyRaw), MLKEM1024PublicKeySize)
	}

	ek, err := mlkem.NewEncapsulationKey1024(publicKeyRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem.NewEncapsulationKey1024 failed: %w", err)
	}

	sharedSecret, ciphertext := ek.Encapsulate()

	return sharedSecret, ciphertext, nil
}

func mlkem768WrapDEK(publicKeyRaw, dek, salt, info []byte) ([]byte, error) {
	sharedSecret, ciphertext, err := MLKEM768Encapsulate(publicKeyRaw)
	if err != nil {
		return nil, err
	}

	wrapKey, err := deriveMLKEMWrapKey(sharedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}

	encryptedDEK, err := gcm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt failed: %w", err)
	}

	wrappedDER, err := asn1.Marshal(MLKEMWrappedKey{
		MLKEMCiphertext: ciphertext,
		EncryptedDEK:    encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return wrappedDER, nil
}

func mlkem768UnwrapDEK(privateKeyRaw, wrappedDER, salt, info []byte) ([]byte, error) {
	if len(privateKeyRaw) != MLKEM768PrivateKeySize {
		return nil, fmt.Errorf("invalid ML-KEM-768 private key size: got %d want %d", len(privateKeyRaw), MLKEM768PrivateKeySize)
	}

	var wrappedKey MLKEMWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}
	if len(wrappedKey.MLKEMCiphertext) != MLKEM768CiphertextSize {
		return nil, fmt.Errorf("invalid ML-KEM-768 ciphertext size: got %d want %d", len(wrappedKey.MLKEMCiphertext), MLKEM768CiphertextSize)
	}

	dk, err := mlkem.NewDecapsulationKey768(privateKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
	}

	sharedSecret, err := dk.Decapsulate(wrappedKey.MLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("mlkem768 decapsulate failed: %w", err)
	}

	wrapKey, err := deriveMLKEMWrapKey(sharedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}

	plaintext, err := gcm.Decrypt(wrappedKey.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt failed: %w", err)
	}

	return plaintext, nil
}

func mlkem1024WrapDEK(publicKeyRaw, dek, salt, info []byte) ([]byte, error) {
	sharedSecret, ciphertext, err := MLKEM1024Encapsulate(publicKeyRaw)
	if err != nil {
		return nil, err
	}

	wrapKey, err := deriveMLKEMWrapKey(sharedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}

	encryptedDEK, err := gcm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt failed: %w", err)
	}

	wrappedDER, err := asn1.Marshal(MLKEMWrappedKey{
		MLKEMCiphertext: ciphertext,
		EncryptedDEK:    encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return wrappedDER, nil
}

func mlkem1024UnwrapDEK(privateKeyRaw, wrappedDER, salt, info []byte) ([]byte, error) {
	if len(privateKeyRaw) != MLKEM1024PrivateKeySize {
		return nil, fmt.Errorf("invalid ML-KEM-1024 private key size: got %d want %d", len(privateKeyRaw), MLKEM1024PrivateKeySize)
	}

	var wrappedKey MLKEMWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}
	if len(wrappedKey.MLKEMCiphertext) != MLKEM1024CiphertextSize {
		return nil, fmt.Errorf("invalid ML-KEM-1024 ciphertext size: got %d want %d", len(wrappedKey.MLKEMCiphertext), MLKEM1024CiphertextSize)
	}

	dk, err := mlkem.NewDecapsulationKey1024(privateKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("mlkem.NewDecapsulationKey1024 failed: %w", err)
	}

	sharedSecret, err := dk.Decapsulate(wrappedKey.MLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("mlkem1024 decapsulate failed: %w", err)
	}

	wrapKey, err := deriveMLKEMWrapKey(sharedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}

	plaintext, err := gcm.Decrypt(wrappedKey.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt failed: %w", err)
	}

	return plaintext, nil
}

func deriveMLKEMWrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = defaultTDFSalt()
	}

	hkdfObj := hkdf.New(sha256.New, sharedSecret, salt, info)
	derivedKey := make([]byte, mlkemWrapKeySize)
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	return derivedKey, nil
}
