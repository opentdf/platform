package ocrypto

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // used for padding which is safe
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type SchemeType string

const (
	RSA SchemeType = "wrapped"
	EC  SchemeType = "ec-wrapped"
)

type Scheme interface {
	// Encrypt encrypts data with public key.
	Encrypt(data []byte) ([]byte, error)

	// PublicKeyInPemFormat Returns public key in pem format.
	PublicKeyInPemFormat() (string, error)

	// Type required to use the scheme for encryption - notably, if it procduces extra metadata.
	Type() SchemeType

	// For EC schemes, this method returns the public part of the ephemeral key.
	EphemeralKey() ([]byte, error)

	// Any extra metadata, e.g. the ephemeral public key for EC scheme keys.
	Metadata() (map[string]string, error)
}

type AsymEncryption struct {
	PublicKey *rsa.PublicKey
}

type ECIES struct {
	PublicKey *ecdh.PublicKey
	private   *ecdh.PrivateKey
}

func FromPEM(publicKeyInPem string) (Scheme, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return &AsymEncryption{pub}, nil
	case *ecdh.PublicKey:
		return newECIES(pub)
	default:
		break
	}

	return nil, errors.New("not an supported type of public key")
}

func newECIES(publicKey *ecdh.PublicKey) (ECIES, err) {
	privateKey, err := publicKey.Curve().GenerateKey(rand.Reader)
	return ECIES{publicKey, privateKey}, err
}

// NewAsymEncryption creates and returns a new AsymEncryption.
// Deprecated: Use FromPEM instead.
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

	return AsymEncryption{}, errors.New("not an supported type of public key")
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

func (e ECIES) Type() SchemeType {
	return EC
}

func (e AsymEncryption) EphemeralKey() ([]byte, error) {
	return nil, errors.New("ephemeral key is not supported for RSA")
}

func (e ECIES) EphemeralKey() ([]byte, error) {
	return e.private.PublicKey().Bytes(), nil
}

func (e AsymEncryption) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func (e ECIES) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["ephemeralPublicKey"] = string(e.private.PublicKey().Bytes())
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
func (e ECIES) Encrypt(data []byte) ([]byte, error) {

	sharedKey, err := e.private.ComputeSecret(e.PublicKey)

	return bytes, nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (e ECIES) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(e.PublicKey)
}

func (e ECIES) deriveKey() (*aes.Key, error) {
	if e.PublicKey == nil {
		return nil, errors.New("failed to encrypt, public key is empty")
	}

	if !e.private.Curve.IsOnCurve(e.PublicKey.X, pub.Y) {
		return nil, fmt.Errorf("invalid public key")
	}

	var secret bytes.Buffer
	secret.Write(k.PublicKey.Bytes(false))

	sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, k.D.Bytes())
	secret.Write([]byte{0x04})

	// Sometimes shared secret coordinates are less than 32 bytes; Big Endian
	l := len(pub.Curve.Params().P.Bytes())
	secret.Write(zeroPad(sx.Bytes(), l))
	secret.Write(zeroPad(sy.Bytes(), l))

	return kdf(secret.Bytes())

	return e.PublicKey
}