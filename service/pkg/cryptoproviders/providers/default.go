// Package providers implements various cryptographic provider implementations
package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/opentdf/platform/service/pkg/cryptoproviders"
)

const (
	// RSA2048KeySize is the size in bytes for a 2048-bit RSA key
	RSA2048KeySize = 256 // 2048 bits = 256 bytes
	// RSA4096KeySize is the size in bytes for a 4096-bit RSA key
	RSA4096KeySize = 512 // 4096 bits = 512 bytes
	// UncompressedECPointFormat indicates an uncompressed EC point
	UncompressedECPointFormat = 0x04
	// CompressedECPointFormatEven indicates a compressed EC point with even Y
	CompressedECPointFormatEven = 0x02
	// CompressedECPointFormatOdd indicates a compressed EC point with odd Y
	CompressedECPointFormatOdd = 0x03
)

// Default implements the cryptographic provider interface using standard Go crypto packages
type Default struct{}

// NewDefault creates a new instance of the default crypto provider
func NewDefault() *Default {
	return &Default{}
}

// Identifier returns the unique identifier for this provider
func (d *Default) Identifier() string {
	return "default"
}

// parsePEMPublicKey parses a PEM encoded public key
func parsePEMPublicKey(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		// Convert ecdsa.PublicKey to ecdh.PublicKey
		ecdhPub, err := pubKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecdsa public key to ecdh: %w", err)
		}
		return ecdhPub, nil
	default:
		return pubKey, nil // Return as is (e.g., *rsa.PublicKey)
	}
}

// parsePEMPrivateKey parses a PEM encoded private key
func parsePEMPrivateKey(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		// Convert ecdsa.PrivateKey to ecdh.PrivateKey
		return priv.ECDH()
	case "PRIVATE KEY":
		// Handle PKCS#8 format
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		switch k := priv.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k.ECDH()
		default:
			return nil, fmt.Errorf("unsupported private key type in PKCS#8")
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// EncryptAsymmetric provides a unified interface for asymmetric encryption
func (d *Default) EncryptAsymmetric(_ context.Context, opts cryptoproviders.EncryptOpts) ([]byte, []byte, error) {
	if opts.KeyRef.IsRSA() {
		pub, err := parsePEMPublicKey(opts.KeyRef.GetRawBytes())
		if err != nil {
			return nil, nil, err
		}

		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("not an RSA public key")
		}

		label := []byte("")
		cipherText, err := rsa.EncryptOAEP(opts.Hash.New(), rand.Reader, rsaPub, opts.Data, label)
		return cipherText, nil, err
	}

	if opts.KeyRef.IsEC() {
		// The KeyRef contains the recipient's public key
		pub, err := parsePEMPublicKey(opts.KeyRef.GetRawBytes())
		if err != nil {
			return nil, nil, err
		}

		ecdhPub, ok := pub.(*ecdh.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("not an ECDH public key")
		}

		// Generate ephemeral key pair
		ephemeralPriv, err := ecdhPub.Curve().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		// Derive shared secret
		secret, err := ephemeralPriv.ECDH(ecdhPub)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute ECDH shared secret: %w", err)
		}

		// Use shared secret to derive encryption key
		sharedKey := sha256.Sum256(secret)

		// Encrypt data using AES-GCM
		block, err := aes.NewCipher(sharedKey[:])
		if err != nil {
			return nil, nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, err
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, nil, err
		}

		// Encrypt and append nonce
		cipherText := gcm.Seal(nonce, nonce, opts.Data, nil)

		// Marshal ephemeral public key
		ephemeralPubKeyBytes, err := x509.MarshalPKIXPublicKey(ephemeralPriv.PublicKey())
		if err != nil {
			return nil, nil, err
		}

		return cipherText, pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY", // Standard PEM type for public keys
			Bytes: ephemeralPubKeyBytes,
		}), nil
	}

	return nil, nil, fmt.Errorf("unsupported algorithm")
}

// DecryptAsymmetric provides a unified interface for asymmetric decryption
func (d *Default) DecryptAsymmetric(_ context.Context, opts cryptoproviders.DecryptOpts) ([]byte, error) {
	if opts.KeyRef.IsRSA() {
		priv, err := parsePEMPrivateKey(opts.KeyRef.GetRawBytes())
		if err != nil {
			return nil, err
		}

		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}

		label := []byte("")
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaPriv, opts.CipherText, label)
	}

	if opts.KeyRef.IsEC() {
		priv, err := parsePEMPrivateKey(opts.KeyRef.GetRawBytes())
		if err != nil {
			return nil, err
		}

		ecdhPriv, ok := priv.(*ecdh.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDH private key")
		}

		pub, err := parsePEMPublicKey(opts.EphemeralKey)
		if err != nil {
			return nil, err
		}
		ecdhPub, ok := pub.(*ecdh.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDH public key (ephemeral)")
		}

		// Derive shared secret
		secret, err := ecdhPriv.ECDH(ecdhPub)
		if err != nil {
			return nil, fmt.Errorf("failed to compute ECDH shared secret: %w", err)
		}

		// Use shared secret to derive decryption key
		sharedKey := sha256.Sum256(secret)

		// Decrypt data using AES-GCM
		block, err := aes.NewCipher(sharedKey[:])
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonceSize := gcm.NonceSize()
		if len(opts.CipherText) < nonceSize {
			return nil, fmt.Errorf("ciphertext too short")
		}

		nonce, cipherText := opts.CipherText[:nonceSize], opts.CipherText[nonceSize:]
		return gcm.Open(nil, nonce, cipherText, nil)
	}

	return nil, fmt.Errorf("unsupported algorithm")
}

// EncryptSymmetric encrypts data using AES-GCM.
func (d *Default) EncryptSymmetric(_ context.Context, key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

// DecryptSymmetric decrypts data using AES-GCM
func (d *Default) DecryptSymmetric(_ context.Context, key []byte, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes", nonceSize)
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plaintext, nil
}
