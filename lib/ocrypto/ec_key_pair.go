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

type KeyType string

const (
	RSA2048Key KeyType = "rsa:2048"
	RSA4096Key KeyType = "rsa:4096"
	EC256Key   KeyType = "ec:secp256r1"
	EC384Key   KeyType = "ec:secp384r1"
	EC521Key   KeyType = "ec:secp521r1"
)

const (
	ECCModeSecp256r1 ECCMode = 0
	ECCModeSecp384r1 ECCMode = 1
	ECCModeSecp521r1 ECCMode = 2
	ECCModeSecp256k1 ECCMode = 3
)

const (
	ECCurveP256Size = 256
	ECCurveP384Size = 384
	ECCurveP521Size = 521
	RSA2048Size     = 2048
	RSA4096Size     = 4096
)

type KeyPair interface {
	PublicKeyInPemFormat() (string, error)
	PrivateKeyInPemFormat() (string, error)
	GetKeyType() KeyType
}

func NewKeyPair(kt KeyType) (KeyPair, error) {
	switch kt {
	case RSA2048Key, RSA4096Key:
		bits, err := RSAKeyTypeToBits(kt)
		if err != nil {
			return nil, err
		}
		return NewRSAKeyPair(bits)
	case EC256Key, EC384Key, EC521Key:
		mode, err := ECKeyTypeToMode(kt)
		if err != nil {
			return nil, err
		}
		return NewECKeyPair(mode)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", kt)
	}
}

type ECKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
}

func IsECKeyType(kt KeyType) bool {
	switch kt { //nolint:exhaustive // only handle ec types
	case EC256Key, EC384Key, EC521Key:
		return true
	default:
		return false
	}
}

func IsRSAKeyType(kt KeyType) bool {
	switch kt { //nolint:exhaustive // only handle rsa types
	case RSA2048Key, RSA4096Key:
		return true
	default:
		return false
	}
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
		return nil, errors.New("unsupported ECC mode")
	default:
		return nil, fmt.Errorf("unsupported ECC mode %d", mode)
	}

	return c, nil
}

func (mode ECCMode) String() string {
	switch mode {
	case ECCModeSecp256r1:
		return "ec:secp256r1"
	case ECCModeSecp384r1:
		return "ec:secp384r1"
	case ECCModeSecp521r1:
		return "ec:secp521r1"
	case ECCModeSecp256k1:
		return "ec:secp256k1"
	}
	return "unspecified"
}

// ECSizeToMode converts a curve size to an ECCMode
func ECSizeToMode(size int) (ECCMode, error) {
	switch size {
	case ECCurveP256Size:
		return ECCModeSecp256r1, nil
	case ECCurveP384Size:
		return ECCModeSecp384r1, nil
	case ECCurveP521Size:
		return ECCModeSecp521r1, nil
	default:
		return 0, fmt.Errorf("unsupported EC curve size: %d", size)
	}
}

func ECKeyTypeToMode(kt KeyType) (ECCMode, error) {
	switch kt { //nolint:exhaustive // only handle ec types
	case EC256Key:
		return ECCModeSecp256r1, nil
	case EC384Key:
		return ECCModeSecp384r1, nil
	case EC521Key:
		return ECCModeSecp521r1, nil
	default:
		return 0, fmt.Errorf("unsupported type: %v", kt)
	}
}

func RSAKeyTypeToBits(kt KeyType) (int, error) {
	switch kt { //nolint:exhaustive // only handle rsa types
	case RSA2048Key:
		return RSA2048Size, nil
	case RSA4096Key:
		return RSA4096Size, nil
	default:
		return 0, fmt.Errorf("unsupported type: %v", kt)
	}
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
		return nil, errors.New("unsupported public key type")
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
		return nil, errors.New("unsupported private key type")
	}
}

// CalculateHKDF generate a key using key derivation function.
func CalculateHKDF(salt []byte, secret []byte) ([]byte, error) {
	hkdfObj := hkdf.New(sha256.New, secret, salt, nil)

	derivedKey := make([]byte, 32) //nolint:mnd // AES-256 requires a 32-byte key
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
		return nil, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(string(pemECPubKey), "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		var ok bool
		if pub, ok = cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, errors.New("failed to parse PEM formatted public key")
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

	return nil, errors.New("not an ec PEM formatted public key")
}

// ECPrivateKeyFromPem generate ec private from pem format
func ECPrivateKeyFromPem(privateECKeyInPem []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(privateECKeyInPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ec x509.ParsePKCS8PrivateKey failed: %w", err)
	}

	switch privateKey := priv.(type) {
	case *ecdsa.PrivateKey:
		return ConvertToECDHPrivateKey(privateKey)
	default:
		break
	}

	return nil, errors.New("not an ec PEM formatted private key")
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
	pkb, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkb,
		},
	)

	return string(publicKeyPem), nil
}

// GetECKeySize returns the curve size from a PEM-encoded EC public key
func GetECKeySize(pemData []byte) (int, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return 0, errors.New("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return 0, errors.New("not an EC key")
	}

	switch ecKey.Curve {
	case elliptic.P256():
		return ECCurveP256Size, nil
	case elliptic.P384():
		return ECCurveP384Size, nil
	case elliptic.P521():
		return ECCurveP521Size, nil
	default:
		return 0, errors.New("unknown curve")
	}
}

// GetKeyType returns the key type (ECKey)
func (keyPair ECKeyPair) GetKeyType() KeyType {
	return EC256Key
}
