package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	xWingPublicKeyPEMType  = "X-WING PUBLIC KEY"
	xWingPrivateKeyPEMType = "X-WING PRIVATE KEY"

	XWingSeedSize       = 32
	XWingPublicKeySize  = mlkem.EncapsulationKeySize768 + 32
	XWingCiphertextSize = mlkem.CiphertextSize768 + 32
)

var xWingLabel = []byte("\\.//^\\")

type XWingKeyPair struct {
	seed [XWingSeedSize]byte
}

type XWingPublicKey struct {
	mlkem  *mlkem.EncapsulationKey768
	x25519 [32]byte
}

type XWingEncryptor struct {
	pub          *XWingPublicKey
	cipherText   []byte
	sharedSecret []byte
}

type XWingDecryptor struct {
	seed [XWingSeedSize]byte
}

func NewXWingKeyPair() (XWingKeyPair, error) {
	var seed [XWingSeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return XWingKeyPair{}, fmt.Errorf("failed to generate X-Wing seed: %w", err)
	}
	return XWingKeyPair{seed: seed}, nil
}

func newXWingPublicKey(raw []byte) (*XWingPublicKey, error) {
	if len(raw) != XWingPublicKeySize {
		return nil, fmt.Errorf("invalid X-Wing public key length: got %d, want %d", len(raw), XWingPublicKeySize)
	}

	mlkemPub, err := mlkem.NewEncapsulationKey768(raw[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, fmt.Errorf("invalid X-Wing ML-KEM public key: %w", err)
	}

	var x25519Pub [32]byte
	copy(x25519Pub[:], raw[mlkem.EncapsulationKeySize768:])

	return &XWingPublicKey{mlkem: mlkemPub, x25519: x25519Pub}, nil
}

func newXWingEncryptor(pub *XWingPublicKey) (*XWingEncryptor, error) {
	if pub == nil {
		return nil, errors.New("x-wing public key is nil")
	}

	mlkemSecret, mlkemCiphertext := pub.mlkem.Encapsulate()

	var x25519Secret [32]byte
	if _, err := io.ReadFull(rand.Reader, x25519Secret[:]); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 secret: %w", err)
	}

	x25519PrivateKey, err := ecdh.X25519().NewPrivateKey(x25519Secret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key: %w", err)
	}
	x25519PublicKey := x25519PrivateKey.PublicKey().Bytes()

	x25519PeerKey, err := ecdh.X25519().NewPublicKey(pub.x25519[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 peer key: %w", err)
	}
	x25519SharedSecret, err := x25519PrivateKey.ECDH(x25519PeerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 shared secret: %w", err)
	}

	ciphertext := make([]byte, 0, XWingCiphertextSize)
	ciphertext = append(ciphertext, mlkemCiphertext...)
	ciphertext = append(ciphertext, x25519PublicKey...)

	sharedSecret := xWingCombiner(mlkemSecret, x25519SharedSecret, x25519PublicKey, pub.x25519[:])
	return &XWingEncryptor{
		pub:          pub,
		cipherText:   ciphertext,
		sharedSecret: sharedSecret,
	}, nil
}

func (keyPair XWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  xWingPrivateKeyPEMType,
		Bytes: keyPair.seed[:],
	})
	return string(privateKeyPEM), nil
}

func (keyPair XWingKeyPair) PublicKeyInPemFormat() (string, error) {
	publicKeyBytes, err := keyPair.publicKeyBytes()
	if err != nil {
		return "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  xWingPublicKeyPEMType,
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

func (keyPair XWingKeyPair) GetKeyType() KeyType {
	return HybridXWingKey
}

func (keyPair XWingKeyPair) publicKeyBytes() ([]byte, error) {
	mlkemSeed, x25519Secret, err := expandXWingSeed(keyPair.seed[:])
	if err != nil {
		return nil, err
	}

	mlkemPriv, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X-Wing ML-KEM key: %w", err)
	}

	x25519PrivateKey, err := ecdh.X25519().NewPrivateKey(x25519Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create X-Wing X25519 private key: %w", err)
	}
	x25519PublicKey := x25519PrivateKey.PublicKey().Bytes()

	publicKeyBytes := make([]byte, 0, XWingPublicKeySize)
	publicKeyBytes = append(publicKeyBytes, mlkemPriv.EncapsulationKey().Bytes()...)
	publicKeyBytes = append(publicKeyBytes, x25519PublicKey...)
	return publicKeyBytes, nil
}

func parseXWingPrivateKey(seed []byte) (*XWingDecryptor, error) {
	if len(seed) != XWingSeedSize {
		return nil, fmt.Errorf("invalid X-Wing private key length: got %d, want %d", len(seed), XWingSeedSize)
	}

	var k XWingDecryptor
	copy(k.seed[:], seed)
	return &k, nil
}

func expandXWingSeed(seed []byte) ([]byte, []byte, error) {
	if len(seed) != XWingSeedSize {
		return nil, nil, fmt.Errorf("invalid X-Wing seed length: got %d, want %d", len(seed), XWingSeedSize)
	}

	expanded := make([]byte, 96)
	h := sha3.NewSHAKE256()
	if _, err := h.Write(seed); err != nil {
		return nil, nil, fmt.Errorf("failed to expand X-Wing seed: %w", err)
	}
	if _, err := io.ReadFull(h, expanded); err != nil {
		return nil, nil, fmt.Errorf("failed to read expanded X-Wing seed: %w", err)
	}

	return expanded[:mlkem.SeedSize], expanded[mlkem.SeedSize:], nil
}

func xWingCombiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(xWingLabel)
	return h.Sum(nil)
}

func (e XWingEncryptor) Type() SchemeType {
	return Hybrid
}

func (e XWingEncryptor) KeyType() KeyType {
	return HybridXWingKey
}

func (e XWingEncryptor) EphemeralKey() []byte {
	return e.cipherText
}

func (e XWingEncryptor) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["encapsulatedKey"] = string(e.EphemeralKey())
	return m, nil
}

func (e XWingEncryptor) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.sharedSecret)
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

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (e XWingEncryptor) PublicKeyInPemFormat() (string, error) {
	if e.pub == nil {
		return "", errors.New("x-wing public key is nil")
	}

	pubBytes := make([]byte, 0, XWingPublicKeySize)
	pubBytes = append(pubBytes, e.pub.mlkem.Bytes()...)
	pubBytes = append(pubBytes, e.pub.x25519[:]...)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  xWingPublicKeyPEMType,
		Bytes: pubBytes,
	})), nil
}

func (d XWingDecryptor) Decrypt(_ []byte) ([]byte, error) {
	return nil, errors.New("ciphertext encapsulation is required for X-Wing decryption")
}

func (d XWingDecryptor) DecryptWithEphemeralKey(data, ephemeral []byte) ([]byte, error) {
	if len(ephemeral) != XWingCiphertextSize {
		return nil, fmt.Errorf("invalid X-Wing ciphertext length: got %d, want %d", len(ephemeral), XWingCiphertextSize)
	}

	mlkemSeed, x25519Secret, err := expandXWingSeed(d.seed[:])
	if err != nil {
		return nil, err
	}

	mlkemPriv, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X-Wing ML-KEM key: %w", err)
	}

	x25519PrivateKey, err := ecdh.X25519().NewPrivateKey(x25519Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create X-Wing X25519 private key: %w", err)
	}
	pkX := x25519PrivateKey.PublicKey().Bytes()

	mlkemCiphertext := ephemeral[:mlkem.CiphertextSize768]
	ctX := ephemeral[mlkem.CiphertextSize768:]

	ssM, err := mlkemPriv.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate X-Wing ML-KEM ciphertext: %w", err)
	}

	peerKey, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X-Wing X25519 ciphertext: %w", err)
	}

	ssX, err := x25519PrivateKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X-Wing X25519 shared secret: %w", err)
	}

	sharedSecret := xWingCombiner(ssM, ssX, ctX, pkX)

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failure: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failure: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open failure: %w", err)
	}

	return plaintext, nil
}
