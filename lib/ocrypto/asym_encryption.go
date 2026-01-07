package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // used for padding which is safe
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

type SchemeType string

const (
	RSA SchemeType = "wrapped"
	EC  SchemeType = "ec-wrapped"
)

type PublicKeyEncryptor interface {
	// Encrypt encrypts data with public key.
	Encrypt(data []byte) ([]byte, error)

	// PublicKeyInPemFormat Returns public key in pem format, or the empty string if not present
	PublicKeyInPemFormat() (string, error)

	// Type required to use the scheme for encryption - notably, if it procduces extra metadata.
	Type() SchemeType

	// KeyType returns the key type, e.g. RSA or EC.
	KeyType() KeyType

	// For EC schemes, this method returns the public part of the ephemeral key.
	// Otherwise, it returns nil.
	EphemeralKey() []byte

	// Any extra metadata, e.g. the ephemeral public key for EC scheme keys.
	Metadata() (map[string]string, error)
}

type AsymEncryption struct {
	PublicKey *rsa.PublicKey
}

type ECEncryptor struct {
	pub  *ecdh.PublicKey
	ek   *ecdh.PrivateKey
	salt []byte
	info []byte
}

func FromPublicPEM(publicKeyInPem string) (PublicKeyEncryptor, error) {
	// TK Move salt and info out of library, into API option functions
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)

	return FromPublicPEMWithSalt(publicKeyInPem, salt, nil)
}

func FromPublicPEMWithSalt(publicKeyInPem string, salt, info []byte) (PublicKeyEncryptor, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return &AsymEncryption{pub}, nil
	case *ecdsa.PublicKey:
		e, err := pub.ECDH()
		if err != nil {
			return nil, err
		}
		return newECIES(e, salt, info)
	case *ecdh.PublicKey:
		return newECIES(pub, salt, info)
	default:
		break
	}

	return nil, errors.New("unsupported type of public key")
}

func newECIES(pub *ecdh.PublicKey, salt, info []byte) (ECEncryptor, error) {
	ek, err := pub.Curve().GenerateKey(rand.Reader)
	return ECEncryptor{pub, ek, salt, info}, err
}

// NewAsymEncryption creates and returns a new AsymEncryption.
//
// Deprecated: Use FromPublicPEM instead.
func NewAsymEncryption(publicKeyInPem string) (AsymEncryption, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return AsymEncryption{}, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return AsymEncryption{pub}, nil
	default:
		break
	}

	return AsymEncryption{}, fmt.Errorf("unsupported public key type: %T", pub)
}

func getPublicPart(publicKeyInPem string) (any, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(publicKeyInPem, "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		pub = cert.PublicKey
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
		}
	}
	return pub, nil
}

func (e AsymEncryption) Type() SchemeType {
	return RSA
}

func (e AsymEncryption) KeyType() KeyType {
	switch e.PublicKey.Size() {
	case RSA2048Size / 8: //nolint:mnd // standard key size in bytes
		return RSA2048Key
	case RSA4096Size / 8: //nolint:mnd // large key size in bytes
		return RSA4096Key
	default:
		bitlen := e.PublicKey.Size() * 8 //nolint:mnd // convert to bits
		return KeyType("rsa:" + strconv.Itoa(bitlen))
	}
}

func (e ECEncryptor) Type() SchemeType {
	return EC
}

func (e ECEncryptor) KeyType() KeyType {
	switch e.pub.Curve() {
	case ecdh.P256():
		return EC256Key
	case ecdh.P384():
		return EC384Key
	case ecdh.P521():
		return EC521Key
	default:
		if n, ok := e.pub.Curve().(fmt.Stringer); ok {
			return KeyType("ec:" + n.String())
		}
		return KeyType("ec:[unknown]")
	}
}

func (e AsymEncryption) EphemeralKey() []byte {
	return nil
}

func (e ECEncryptor) EphemeralKey() []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(e.ek.PublicKey())
	if err != nil {
		return nil
	}
	return publicKeyBytes
}

func (e AsymEncryption) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func (e ECEncryptor) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["ephemeralPublicKey"] = string(e.EphemeralKey())
	return m, nil
}

func (e AsymEncryption) Encrypt(data []byte) ([]byte, error) {
	if e.PublicKey == nil {
		return nil, errors.New("failed to encrypt, public key is empty")
	}

	bytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, e.PublicKey, data, nil) //nolint:gosec // used for padding which is safe
	if err != nil {
		return nil, fmt.Errorf("rsa.EncryptOAEP failed: %w", err)
	}

	return bytes, nil
}

func publicKeyInPemFormat(pk any) (string, error) {
	if pk == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return string(publicKeyPem), nil
}

func (e AsymEncryption) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(e.PublicKey)
}

// Encrypts the data with the EC public key.
func (e ECEncryptor) Encrypt(data []byte) ([]byte, error) {
	ikm, err := e.ek.ECDH(e.pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh failure: %w", err)
	}

	hkdfObj := hkdf.New(sha256.New, ikm, e.salt, e.info)

	derivedKey := make([]byte, 32) //nolint:mnd // AES-256 requires a 32-byte key
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	// Encrypt data with derived key using aes-gcm
	block, err := aes.NewCipher(derivedKey)
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (e ECEncryptor) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(e.ek.Public())
}
