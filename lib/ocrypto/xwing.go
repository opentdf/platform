package ocrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

const (
	HybridXWingKey KeyType = "hpqt:xwing"

	XWingPublicKeySize  = xwing.PublicKeySize
	XWingPrivateKeySize = xwing.PrivateKeySize
	XWingCiphertextSize = xwing.CiphertextSize

	PEMBlockXWingPublicKey  = "XWING PUBLIC KEY"
	PEMBlockXWingPrivateKey = "XWING PRIVATE KEY"
)

type XWingWrappedKey struct {
	XWingCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK    []byte `asn1:"tag:1"`
}

type XWingKeyPair struct {
	publicKey  []byte
	privateKey []byte
}

type XWingEncryptor struct {
	publicKey []byte
	salt      []byte
	info      []byte
}

type XWingDecryptor struct {
	privateKey []byte
	salt       []byte
	info       []byte
}

func NewXWingKeyPair() (XWingKeyPair, error) {
	sk, pk, err := xwing.GenerateKeyPair(rand.Reader)
	if err != nil {
		return XWingKeyPair{}, fmt.Errorf("xwing.GenerateKeyPair failed: %w", err)
	}

	publicKey := make([]byte, XWingPublicKeySize)
	privateKey := make([]byte, XWingPrivateKeySize)
	pk.Pack(publicKey)
	sk.Pack(privateKey)

	return XWingKeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func (k XWingKeyPair) PublicKeyInPemFormat() (string, error) {
	return rawToPEM(PEMBlockXWingPublicKey, k.publicKey, XWingPublicKeySize)
}

func (k XWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	return rawToPEM(PEMBlockXWingPrivateKey, k.privateKey, XWingPrivateKeySize)
}

func (k XWingKeyPair) GetKeyType() KeyType {
	return HybridXWingKey
}

func XWingPubKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockXWingPublicKey, XWingPublicKeySize)
}

func XWingPrivateKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockXWingPrivateKey, XWingPrivateKeySize)
}

func NewXWingEncryptor(publicKey, salt, info []byte) (*XWingEncryptor, error) {
	if len(publicKey) != XWingPublicKeySize {
		return nil, fmt.Errorf("invalid X-Wing public key size: got %d want %d", len(publicKey), XWingPublicKeySize)
	}

	return &XWingEncryptor{
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
	}, nil
}

func (e *XWingEncryptor) Encrypt(data []byte) ([]byte, error) {
	return xwingWrapDEK(e.publicKey, data, e.salt, e.info)
}

func (e *XWingEncryptor) PublicKeyInPemFormat() (string, error) {
	return rawToPEM(PEMBlockXWingPublicKey, e.publicKey, XWingPublicKeySize)
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

func NewXWingDecryptor(privateKey []byte) (*XWingDecryptor, error) {
	return NewSaltedXWingDecryptor(privateKey, defaultTDFSalt(), nil)
}

func NewSaltedXWingDecryptor(privateKey, salt, info []byte) (*XWingDecryptor, error) {
	if len(privateKey) != XWingPrivateKeySize {
		return nil, fmt.Errorf("invalid X-Wing private key size: got %d want %d", len(privateKey), XWingPrivateKeySize)
	}

	return &XWingDecryptor{
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
	}, nil
}

func (d *XWingDecryptor) Decrypt(data []byte) ([]byte, error) {
	return xwingUnwrapDEK(d.privateKey, data, d.salt, d.info)
}

func XWingWrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return xwingWrapDEK(publicKeyRaw, dek, defaultTDFSalt(), nil)
}

func XWingUnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return xwingUnwrapDEK(privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

// XWingEncapsulate performs the X-Wing KEM encapsulation, returning the shared
// secret and ciphertext without applying KDF or encryption.
func XWingEncapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	if len(publicKeyRaw) != XWingPublicKeySize {
		return nil, nil, fmt.Errorf("invalid X-Wing public key size: got %d want %d", len(publicKeyRaw), XWingPublicKeySize)
	}

	sharedSecret, ciphertext, err := xwing.Encapsulate(publicKeyRaw, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing.Encapsulate failed: %w", err)
	}

	return sharedSecret, ciphertext, nil
}

func xwingWrapDEK(publicKeyRaw, dek, salt, info []byte) ([]byte, error) {
	sharedSecret, ciphertext, err := XWingEncapsulate(publicKeyRaw)
	if err != nil {
		return nil, err
	}

	wrapKey, err := deriveXWingWrapKey(sharedSecret, salt, info)
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

	wrappedDER, err := asn1.Marshal(XWingWrappedKey{
		XWingCiphertext: ciphertext,
		EncryptedDEK:    encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return wrappedDER, nil
}

func xwingUnwrapDEK(privateKeyRaw, wrappedDER, salt, info []byte) ([]byte, error) {
	if len(privateKeyRaw) != XWingPrivateKeySize {
		return nil, fmt.Errorf("invalid X-Wing private key size: got %d want %d", len(privateKeyRaw), XWingPrivateKeySize)
	}

	var wrappedKey XWingWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}
	if len(wrappedKey.XWingCiphertext) != XWingCiphertextSize {
		return nil, fmt.Errorf("invalid X-Wing ciphertext size: got %d want %d", len(wrappedKey.XWingCiphertext), XWingCiphertextSize)
	}

	sharedSecret := xwing.Decapsulate(wrappedKey.XWingCiphertext, privateKeyRaw)

	wrapKey, err := deriveXWingWrapKey(sharedSecret, salt, info)
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

func deriveXWingWrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = defaultTDFSalt()
	}

	hkdfObj := hkdf.New(sha256.New, sharedSecret, salt, info)
	derivedKey := make([]byte, xwing.SharedKeySize)
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	return derivedKey, nil
}

func decodeSizedPEMBlock(data []byte, blockType string, expectedSize int) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM formatted %s", blockType)
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("unexpected PEM block type: got %s want %s", block.Type, blockType)
	}
	if len(block.Bytes) != expectedSize {
		return nil, fmt.Errorf("invalid %s size: got %d want %d", blockType, len(block.Bytes), expectedSize)
	}

	return append([]byte(nil), block.Bytes...), nil
}
