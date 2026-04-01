package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/xwing"
)

const (
	// XWingPublicKeySize is the size of an X-Wing public key (32 bytes X25519 + 1184 bytes ML-KEM-768).
	XWingPublicKeySize = xwing.PublicKeySize // 1216

	// XWingPrivateKeySize is the size of an X-Wing private key seed.
	XWingPrivateKeySize = xwing.PrivateKeySize // 32

	// XWingCiphertextSize is the size of an X-Wing ciphertext (32 bytes X25519 + 1088 bytes ML-KEM-768).
	XWingCiphertextSize = xwing.CiphertextSize // 1120

	// XWingSharedSecretSize is the size of an X-Wing shared secret.
	XWingSharedSecretSize = xwing.SharedKeySize // 32

	// PEMBlockXWingPublicKey is the PEM block type for X-Wing public keys.
	PEMBlockXWingPublicKey = "XWING PUBLIC KEY"

	// PEMBlockXWingPrivateKey is the PEM block type for X-Wing private keys.
	PEMBlockXWingPrivateKey = "XWING PRIVATE KEY"
)

// XWingWrappedKey is the ASN.1 structure stored in the KAO's wrapped_key field
// for hybrid-wrapped KAOs. It bundles the X-Wing ciphertext (from which the
// shared secret is derived via decapsulation) with the AES-GCM encrypted DEK.
type XWingWrappedKey struct {
	XWingCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK    []byte `asn1:"tag:1"` // nonce || AES-GCM ciphertext+tag
}

// XWingKeyPair holds an X-Wing key pair and implements the KeyPair interface.
type XWingKeyPair struct {
	pk *xwing.PublicKey
	sk *xwing.PrivateKey
}

// NewXWingKeyPair generates a new X-Wing key pair.
func NewXWingKeyPair() (XWingKeyPair, error) {
	sk, pk, err := xwing.GenerateKeyPair(rand.Reader)
	if err != nil {
		return XWingKeyPair{}, fmt.Errorf("xwing.GenerateKeyPair failed: %w", err)
	}
	return XWingKeyPair{pk: pk, sk: sk}, nil
}

// PublicKeyInPemFormat returns the public key in PEM format with block type "XWING PUBLIC KEY".
func (kp XWingKeyPair) PublicKeyInPemFormat() (string, error) {
	if kp.pk == nil {
		return "", errors.New("xwing: public key is nil")
	}
	buf := make([]byte, XWingPublicKeySize)
	kp.pk.Pack(buf)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  PEMBlockXWingPublicKey,
		Bytes: buf,
	})), nil
}

// PrivateKeyInPemFormat returns the private key seed in PEM format with block type "XWING PRIVATE KEY".
func (kp XWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	if kp.sk == nil {
		return "", errors.New("xwing: private key is nil")
	}
	buf := make([]byte, XWingPrivateKeySize)
	kp.sk.Pack(buf)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  PEMBlockXWingPrivateKey,
		Bytes: buf,
	})), nil
}

// GetKeyType returns the HybridXWingKey key type.
func (kp XWingKeyPair) GetKeyType() KeyType {
	return HybridXWingKey
}

// XWingPubKeyFromPem parses a PEM-encoded X-Wing public key and returns the raw bytes.
func XWingPubKeyFromPem(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("xwing: failed to parse PEM block")
	}
	if block.Type != PEMBlockXWingPublicKey {
		return nil, fmt.Errorf("xwing: unexpected PEM block type %q, want %q", block.Type, PEMBlockXWingPublicKey)
	}
	if len(block.Bytes) != XWingPublicKeySize {
		return nil, fmt.Errorf("xwing: invalid public key size: got %d, want %d", len(block.Bytes), XWingPublicKeySize)
	}
	return block.Bytes, nil
}

// XWingPrivateKeyFromPem parses a PEM-encoded X-Wing private key seed and returns the raw bytes.
func XWingPrivateKeyFromPem(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("xwing: failed to parse PEM block")
	}
	if block.Type != PEMBlockXWingPrivateKey {
		return nil, fmt.Errorf("xwing: unexpected PEM block type %q, want %q", block.Type, PEMBlockXWingPrivateKey)
	}
	if len(block.Bytes) != XWingPrivateKeySize {
		return nil, fmt.Errorf("xwing: invalid private key size: got %d, want %d", len(block.Bytes), XWingPrivateKeySize)
	}
	return block.Bytes, nil
}

// XWingWrapDEK encapsulates a shared secret with the X-Wing public key, then
// uses that shared secret to AES-GCM encrypt the DEK. Returns an ASN.1 DER
// encoded XWingWrappedKey suitable for the KAO wrapped_key field.
func XWingWrapDEK(publicKeyRaw []byte, dek []byte) ([]byte, error) {
	if len(publicKeyRaw) != XWingPublicKeySize {
		return nil, fmt.Errorf("xwing: invalid public key size: got %d, want %d", len(publicKeyRaw), XWingPublicKeySize)
	}

	ss, ct, err := xwing.Encapsulate(publicKeyRaw, nil)
	if err != nil {
		return nil, fmt.Errorf("xwing: encapsulation failed: %w", err)
	}

	encryptedDEK, err := aesGCMEncrypt(ss, dek)
	if err != nil {
		return nil, fmt.Errorf("xwing: AES-GCM encrypt failed: %w", err)
	}

	envelope := XWingWrappedKey{
		XWingCiphertext: ct,
		EncryptedDEK:    encryptedDEK,
	}

	der, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("xwing: ASN.1 marshal failed: %w", err)
	}

	return der, nil
}

// XWingUnwrapDEK decapsulates the shared secret from the X-Wing ciphertext
// using the private key, then uses the shared secret to AES-GCM decrypt the DEK.
func XWingUnwrapDEK(privateKeyRaw []byte, wrappedDER []byte) ([]byte, error) {
	if len(privateKeyRaw) != XWingPrivateKeySize {
		return nil, fmt.Errorf("xwing: invalid private key size: got %d, want %d", len(privateKeyRaw), XWingPrivateKeySize)
	}

	var envelope XWingWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &envelope)
	if err != nil {
		return nil, fmt.Errorf("xwing: ASN.1 unmarshal failed: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("xwing: trailing data after ASN.1 envelope")
	}

	if len(envelope.XWingCiphertext) != XWingCiphertextSize {
		return nil, fmt.Errorf("xwing: invalid ciphertext size: got %d, want %d", len(envelope.XWingCiphertext), XWingCiphertextSize)
	}

	ss := xwing.Decapsulate(envelope.XWingCiphertext, privateKeyRaw)

	dek, err := aesGCMDecrypt(ss, envelope.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("xwing: AES-GCM decrypt failed: %w", err)
	}

	return dek, nil
}

// XWingEncryptor implements PublicKeyEncryptor for hybrid X-Wing wrapping.
type XWingEncryptor struct {
	publicKeyRaw []byte
}

func (e *XWingEncryptor) Encrypt(data []byte) ([]byte, error) {
	return XWingWrapDEK(e.publicKeyRaw, data)
}

func (e *XWingEncryptor) PublicKeyInPemFormat() (string, error) {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  PEMBlockXWingPublicKey,
		Bytes: e.publicKeyRaw,
	})), nil
}

func (e *XWingEncryptor) Type() SchemeType {
	return Hybrid
}

func (e *XWingEncryptor) KeyType() KeyType {
	return HybridXWingKey
}

func (e *XWingEncryptor) EphemeralKey() []byte {
	return nil
}

func (e *XWingEncryptor) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

// XWingDecryptor implements PrivateKeyDecryptor for hybrid X-Wing unwrapping.
type XWingDecryptor struct {
	privateKeyRaw []byte
}

// NewXWingDecryptor creates a new XWingDecryptor from raw private key bytes.
func NewXWingDecryptor(privateKeyRaw []byte) (XWingDecryptor, error) {
	if len(privateKeyRaw) != XWingPrivateKeySize {
		return XWingDecryptor{}, fmt.Errorf("xwing: invalid private key size: got %d, want %d", len(privateKeyRaw), XWingPrivateKeySize)
	}
	return XWingDecryptor{privateKeyRaw: privateKeyRaw}, nil
}

// Decrypt unwraps a DEK from an ASN.1 encoded XWingWrappedKey.
func (d XWingDecryptor) Decrypt(data []byte) ([]byte, error) {
	return XWingUnwrapDEK(d.privateKeyRaw, data)
}

// aesGCMEncrypt encrypts data with AES-256-GCM using the given key.
// Returns nonce || ciphertext+tag.
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// aesGCMDecrypt decrypts data encrypted with AES-256-GCM.
// Expects nonce || ciphertext+tag.
func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
