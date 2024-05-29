package ocrypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
)

type ECCMode uint8

const (
	ECCModeSecp256r1 ECCMode = 0
	ECCModeSecp384r1 ECCMode = 1
	ECCModeSecp521r1 ECCMode = 2
	ECCModeSecp256k1 ECCMode = 3
)

type ECKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
}

// GetECCurveFromECCMode return elliptic curve from ecc mode
func GetECCurveFromECCMode(mode ECCMode) (elliptic.Curve, error) {
	var c elliptic.Curve

	switch mode {
	case ECCModeSecp256r1:
		c = elliptic.P256()
	case ECCModeSecp384r1:
		c = elliptic.P384()
	case ECCModeSecp521r1:
		c = elliptic.P521()
	case ECCModeSecp256k1:
		// TODO FIXME - unsupported?
		return nil, errors.New("unsupported nanoTDF ecc mode")
	default:
		return nil, fmt.Errorf("unsupported nanoTDF ecc mode %d", mode)
	}

	return c, nil
}

// NewECKeyPair Generates an EC key pair of the given bit size.
func NewECKeyPair(mode ECCMode) (ECKeyPair, error) {
	var c elliptic.Curve

	var err error

	c, err = GetECCurveFromECCMode(mode)
	if err != nil {
		return ECKeyPair{}, err
	}

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return ECKeyPair{}, fmt.Errorf("ec.GenerateKey failed: %w", err)
	}

	ecKeyPair := ECKeyPair{PrivateKey: privateKey}
	return ecKeyPair, nil
}

// PrivateKeyInPemFormat Returns private key in pem format.
func (keyPair ECKeyPair) PrivateKeyInPemFormat() (string, error) {
	if keyPair.PrivateKey == nil {
		return "", errors.New("failed to generate PEM formatted private key")
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(keyPair.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKCS8PrivateKey failed: %w", err)
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return string(privateKeyPem), nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (keyPair ECKeyPair) PublicKeyInPemFormat() (string, error) {
	if keyPair.PrivateKey == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PrivateKey.PublicKey)
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

// KeySize Return the size of this ec key pair.
func (keyPair ECKeyPair) KeySize() (int, error) {
	if keyPair.PrivateKey == nil {
		return -1, errors.New("failed to return key size")
	}
	return keyPair.PrivateKey.Params().N.BitLen(), nil
}

// CompressedECPublicKey - return a compressed key from the supplied curve and public key
func CompressedECPublicKey(mode ECCMode, pubKey ecdsa.PublicKey) ([]byte, error) {
	curve, err := GetECCurveFromECCMode(mode)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
	}

	compressedKey := elliptic.MarshalCompressed(curve, pubKey.X, pubKey.Y)

	return compressedKey, nil
}

// ConvertToECDHPublicKey convert the ec public key to ECDH public key
func ConvertToECDHPublicKey(key interface{}) (*ecdh.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Convert from ecdsa.PublicKey to ECDHPublicKey
		return k.ECDH()
	case *ecdh.PublicKey:
		// No conversion needed
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

// ConvertToECDHPrivateKey convert the ec private key to ECDH private key
func ConvertToECDHPrivateKey(key interface{}) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		// Convert from ecdsa.PublicKey to ECDHPublicKey
		return k.ECDH()
	case *ecdh.PrivateKey:
		// No conversion needed
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// CalculateHKDF generate a key using key derivation function.
func CalculateHKDF(salt []byte, secret []byte) ([]byte, error) {
	hkdfObj := hkdf.New(sha256.New, secret, salt, nil)

	derivedKey := make([]byte, len(secret))
	_, err := io.ReadFull(hkdfObj, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive hkdf key: %w", err)
	}

	return derivedKey, nil
}

// ComputeECDSASig compute ecdsa signature
func ComputeECDSASig(digest []byte, privKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		return nil, nil, err
	}

	return r.Bytes(), s.Bytes(), nil
}

// VerifyECDSASig verify ecdsa signature.
func VerifyECDSASig(digest, r, s []byte, pubKey *ecdsa.PublicKey) bool {
	rAsBigInt := new(big.Int)
	rAsBigInt.SetBytes(r)

	sAsBigInt := new(big.Int)
	sAsBigInt.SetBytes(s)

	return ecdsa.Verify(pubKey, digest, rAsBigInt, sAsBigInt)
}

// ECPubKeyFromPem generate ec public from pem format
func ECPubKeyFromPem(pemECPubKey []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(pemECPubKey)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(string(pemECPubKey), "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		var ok bool
		if pub, ok = cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("failed to parse PEM formatted public key")
		}
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
		}
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return ConvertToECDHPublicKey(pub)
	default:
		break
	}

	return nil, fmt.Errorf("not an ec PEM formatted public key")
}

// ECPrivateKeyFromPem generate ec private from pem format
func ECPrivateKeyFromPem(privateECKeyInPem []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(privateECKeyInPem)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}

	switch privateKey := priv.(type) {
	case *ecdsa.PrivateKey:
		return ConvertToECDHPrivateKey(privateKey)
	default:
		break
	}

	return nil, fmt.Errorf("not an ec PEM formatted private key")
}

// ComputeECDHKey calculate shared secret from public key from one party and the private key from another party.
func ComputeECDHKey(privateKeyInPem []byte, publicKeyInPem []byte) ([]byte, error) {
	ecdhPrivateKey, err := ECPrivateKeyFromPem(privateKeyInPem)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPrivateKeyFromPem failed: %w", err)
	}

	ecdhPublicKey, err := ECPubKeyFromPem(publicKeyInPem)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	sharedKey, err := ecdhPrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("there was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

func ComputeECDHKeyFromEC(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	ecdhPrivateKey, err := ConvertToECDHPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPrivateKeyFromPem failed: %w", err)
	}

	ecdhPublicKey, err := ConvertToECDHPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	sharedKey, err := ecdhPrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("there was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

func ComputeECDHKeyFromECDHKeys(publicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey) ([]byte, error) {
	sharedKey, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("there was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

// UncompressECPubKey create EC public key from compressed form
func UncompressECPubKey(curve elliptic.Curve, compressedPubKey []byte) (*ecdsa.PublicKey, error) {
	// Converting ephemeralPublicKey byte array to *big.Int
	x, y := elliptic.UnmarshalCompressed(curve, compressedPubKey)
	if x == nil {
		return nil, errors.New("failed to unmarshal compressed public key")
	}
	// Creating ecdsa.PublicKey from *big.Int
	ephemeralECDSAPublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return ephemeralECDSAPublicKey, nil
}

// ECPrivateKeyInPemFormat Returns private key in pem format.
func ECPrivateKeyInPemFormat(privateKey ecdsa.PrivateKey) (string, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKCS8PrivateKey failed: %w", err)
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return string(privateKeyPem), nil
}

// ECPublicKeyInPemFormat Returns public key in pem format.
func ECPublicKeyInPemFormat(publicKey ecdsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
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
