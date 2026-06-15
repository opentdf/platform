package ocrypto

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// errNotMLKEM is returned by the ML-KEM SPKI / PKCS#8 parsers when the supplied
// DER blob is not an ML-KEM key, signalling the caller to fall through to
// other algorithm parsers.
var errNotMLKEM = errors.New("not an ML-KEM key")

const (
	MLKEM768PublicKeySize   = 1184 // mlkem768 encapsulation key
	MLKEM768PrivateKeySize  = 64   // mlkem768 seed (d || z)
	MLKEM768CiphertextSize  = 1088 // mlkem768 ciphertext
	MLKEM1024PublicKeySize  = 1568 // mlkem1024 encapsulation key
	MLKEM1024PrivateKeySize = 64   // mlkem1024 seed (d || z)
	MLKEM1024CiphertextSize = 1568 // mlkem1024 ciphertext

	mlkemWrapKeySize = 32 // AES-256 key size for wrap key derivation
)

// NIST-assigned OIDs for ML-KEM (FIPS 203).
var (
	OIDMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	OIDMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

type mlkemAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type mlkemSPKI struct {
	Algorithm mlkemAlgorithmIdentifier
	PublicKey asn1.BitString
}

// mlkemPKCS8 mirrors RFC 5958 OneAsymmetricKey v1.
type mlkemPKCS8 struct {
	Version    int
	Algorithm  mlkemAlgorithmIdentifier
	PrivateKey []byte
}

const bitsPerByte = 8

// marshalMLKEMPublicSPKI encodes a raw ML-KEM encapsulation key as RFC 5280 SubjectPublicKeyInfo.
func marshalMLKEMPublicSPKI(oid asn1.ObjectIdentifier, rawKey []byte) ([]byte, error) {
	return asn1.Marshal(mlkemSPKI{
		Algorithm: mlkemAlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: rawKey, BitLength: len(rawKey) * bitsPerByte},
	})
}

// marshalMLKEMPrivatePKCS8 encodes the ML-KEM seed as RFC 5958 OneAsymmetricKey,
// with the inner ML-KEM-PrivateKey CHOICE selected as [0] IMPLICIT OCTET STRING (seed).
func marshalMLKEMPrivatePKCS8(oid asn1.ObjectIdentifier, seed []byte) ([]byte, error) {
	inner, err := asn1.MarshalWithParams(seed, "tag:0,implicit")
	if err != nil {
		return nil, fmt.Errorf("asn1.MarshalWithParams seed failed: %w", err)
	}
	return asn1.Marshal(mlkemPKCS8{
		Version:    0,
		Algorithm:  mlkemAlgorithmIdentifier{Algorithm: oid},
		PrivateKey: inner,
	})
}

// ParseMLKEMPublicSPKI returns the OID and raw encapsulation key bytes from an
// SPKI DER blob if the algorithm is ML-KEM-768 or ML-KEM-1024. If the blob is
// not ML-KEM the sentinel errNotMLKEM is returned so the caller can fall
// through to other parsers.
func ParseMLKEMPublicSPKI(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var s mlkemSPKI
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil || len(rest) != 0 {
		return nil, nil, errNotMLKEM
	}
	var oid asn1.ObjectIdentifier
	switch {
	case s.Algorithm.Algorithm.Equal(OIDMLKEM768):
		oid = OIDMLKEM768
	case s.Algorithm.Algorithm.Equal(OIDMLKEM1024):
		oid = OIDMLKEM1024
	default:
		return nil, nil, errNotMLKEM
	}
	if s.PublicKey.BitLength%bitsPerByte != 0 {
		return nil, nil, errors.New("ML-KEM SPKI bit string is not byte-aligned")
	}
	return oid, s.PublicKey.RightAlign(), nil
}

// parseMLKEMPrivatePKCS8 returns the OID and raw seed bytes from a PKCS#8 DER
// blob if the algorithm is ML-KEM-768 or ML-KEM-1024. If the blob is not
// ML-KEM the sentinel errNotMLKEM is returned so the caller can fall through
// to other parsers.
func parseMLKEMPrivatePKCS8(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var p mlkemPKCS8
	rest, err := asn1.Unmarshal(der, &p)
	if err != nil || len(rest) != 0 {
		return nil, nil, errNotMLKEM
	}
	var oid asn1.ObjectIdentifier
	switch {
	case p.Algorithm.Algorithm.Equal(OIDMLKEM768):
		oid = OIDMLKEM768
	case p.Algorithm.Algorithm.Equal(OIDMLKEM1024):
		oid = OIDMLKEM1024
	default:
		return nil, nil, errNotMLKEM
	}

	var innerSeed []byte
	innerRest, err := asn1.UnmarshalWithParams(p.PrivateKey, &innerSeed, "tag:0,implicit")
	if err != nil || len(innerRest) != 0 {
		return nil, nil, fmt.Errorf("ML-KEM PKCS#8 inner seed parse failed: %w", err)
	}
	return oid, innerSeed, nil
}

type MLKEMWrappedKey struct {
	MLKEMCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK    []byte `asn1:"tag:1"`
}

type mlkemParams struct {
	oid              asn1.ObjectIdentifier
	publicKeySize    int
	privateKeySize   int
	ciphertextSize   int
	keyType          KeyType
	displayName      string
	encapsulate      func(publicKey []byte) ([]byte, []byte, error)
	newDecapsulation func(privateKey []byte) (mlkemDecapsulationKey, error)
}

type mlkemDecapsulationKey interface {
	Decapsulate(ciphertext []byte) ([]byte, error)
}

var mlkem768Params = mlkemParams{
	oid:            OIDMLKEM768,
	publicKeySize:  MLKEM768PublicKeySize,
	privateKeySize: MLKEM768PrivateKeySize,
	ciphertextSize: MLKEM768CiphertextSize,
	keyType:        MLKEM768Key,
	displayName:    "ML-KEM-768",
	encapsulate: func(publicKey []byte) ([]byte, []byte, error) {
		ek, err := mlkem.NewEncapsulationKey768(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem.NewEncapsulationKey768 failed: %w", err)
		}
		sharedSecret, ciphertext := ek.Encapsulate()
		return sharedSecret, ciphertext, nil
	},
	newDecapsulation: func(privateKey []byte) (mlkemDecapsulationKey, error) {
		dk, err := mlkem.NewDecapsulationKey768(privateKey)
		if err != nil {
			return nil, fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
		}
		return dk, nil
	},
}

var mlkem1024Params = mlkemParams{
	oid:            OIDMLKEM1024,
	publicKeySize:  MLKEM1024PublicKeySize,
	privateKeySize: MLKEM1024PrivateKeySize,
	ciphertextSize: MLKEM1024CiphertextSize,
	keyType:        MLKEM1024Key,
	displayName:    "ML-KEM-1024",
	encapsulate: func(publicKey []byte) ([]byte, []byte, error) {
		ek, err := mlkem.NewEncapsulationKey1024(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem.NewEncapsulationKey1024 failed: %w", err)
		}
		sharedSecret, ciphertext := ek.Encapsulate()
		return sharedSecret, ciphertext, nil
	},
	newDecapsulation: func(privateKey []byte) (mlkemDecapsulationKey, error) {
		dk, err := mlkem.NewDecapsulationKey1024(privateKey)
		if err != nil {
			return nil, fmt.Errorf("mlkem.NewDecapsulationKey1024 failed: %w", err)
		}
		return dk, nil
	},
}

type MLKEMEncryptor struct {
	publicKey []byte
	salt      []byte
	info      []byte
	params    *mlkemParams
}

type MLKEMDecryptor struct {
	privateKey []byte
	salt       []byte
	info       []byte
	params     *mlkemParams
}

func NewMLKEM768Encryptor(publicKey, salt, info []byte) (*MLKEMEncryptor, error) {
	return newMLKEMEncryptor(&mlkem768Params, publicKey, salt, info)
}

func NewMLKEM1024Encryptor(publicKey, salt, info []byte) (*MLKEMEncryptor, error) {
	return newMLKEMEncryptor(&mlkem1024Params, publicKey, salt, info)
}

func newMLKEMEncryptor(params *mlkemParams, publicKey, salt, info []byte) (*MLKEMEncryptor, error) {
	if len(publicKey) != params.publicKeySize {
		return nil, fmt.Errorf("invalid %s public key size: got %d want %d", params.displayName, len(publicKey), params.publicKeySize)
	}

	return &MLKEMEncryptor{
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
		params:    params,
	}, nil
}

func (e *MLKEMEncryptor) Encrypt(data []byte) ([]byte, error) {
	return mlkemWrapDEK(e.params, e.publicKey, data, e.salt, e.info)
}

func (e *MLKEMEncryptor) PublicKeyInPemFormat() (string, error) {
	der, err := marshalMLKEMPublicSPKI(e.params.oid, e.publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal %s SPKI failed: %w", e.params.displayName, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func (e *MLKEMEncryptor) Type() SchemeType {
	return MLKEM
}

func (e *MLKEMEncryptor) KeyType() KeyType {
	return e.params.keyType
}

func (e *MLKEMEncryptor) EphemeralKey() []byte {
	return nil
}

func (e *MLKEMEncryptor) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func NewMLKEM768Decryptor(privateKey []byte) (*MLKEMDecryptor, error) {
	return NewSaltedMLKEM768Decryptor(privateKey, defaultTDFSalt(), nil)
}

func NewSaltedMLKEM768Decryptor(privateKey, salt, info []byte) (*MLKEMDecryptor, error) {
	return newMLKEMDecryptor(&mlkem768Params, privateKey, salt, info)
}

func NewMLKEM1024Decryptor(privateKey []byte) (*MLKEMDecryptor, error) {
	return NewSaltedMLKEM1024Decryptor(privateKey, defaultTDFSalt(), nil)
}

func NewSaltedMLKEM1024Decryptor(privateKey, salt, info []byte) (*MLKEMDecryptor, error) {
	return newMLKEMDecryptor(&mlkem1024Params, privateKey, salt, info)
}

func newMLKEMDecryptor(params *mlkemParams, privateKey, salt, info []byte) (*MLKEMDecryptor, error) {
	if len(privateKey) != params.privateKeySize {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", params.displayName, len(privateKey), params.privateKeySize)
	}

	return &MLKEMDecryptor{
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
		params:     params,
	}, nil
}

func (d *MLKEMDecryptor) Decrypt(data []byte) ([]byte, error) {
	return mlkemUnwrapDEK(d.params, d.privateKey, data, d.salt, d.info)
}

// normalizeMLKEMPublicKey detects the input format and returns raw key bytes.
// Accepts: raw key (1184/1568 bytes), SPKI DER (1206/1590 bytes), or PEM-wrapped SPKI.
func normalizeMLKEMPublicKey(input []byte, expectedRawSize int, expectedOID asn1.ObjectIdentifier) ([]byte, error) {
	// Fast path: already raw?
	if len(input) == expectedRawSize {
		return input, nil
	}

	// Check for PEM format
	if bytes.HasPrefix(input, []byte("-----BEGIN")) {
		block, _ := pem.Decode(input)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("expected %s PEM block, got %s", "PUBLIC KEY", block.Type)
		}
		// Continue with DER bytes
		input = block.Bytes
	}

	// Try parsing as SPKI DER
	oid, rawKey, err := ParseMLKEMPublicSPKI(input)
	if err != nil {
		if errors.Is(err, errNotMLKEM) {
			return nil, errors.New("not an ML-KEM key in SPKI format")
		}
		return nil, fmt.Errorf("failed to parse SPKI: %w", err)
	}

	// Verify OID matches expected variant
	if !oid.Equal(expectedOID) {
		return nil, fmt.Errorf("OID mismatch: expected %v, got %v", expectedOID, oid)
	}

	// Verify extracted key is correct size
	if len(rawKey) != expectedRawSize {
		return nil, fmt.Errorf("extracted key has wrong size: got %d want %d", len(rawKey), expectedRawSize)
	}

	return rawKey, nil
}

func MLKEM768WrapDEK(publicKey, dek []byte) ([]byte, error) {
	// Normalize input to raw key bytes (handles raw, SPKI DER, or PEM)
	rawKey, err := normalizeMLKEMPublicKey(publicKey, mlkem768Params.publicKeySize, mlkem768Params.oid)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 public key: %w", err)
	}
	return mlkemWrapDEK(&mlkem768Params, rawKey, dek, defaultTDFSalt(), nil)
}

func MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return mlkemUnwrapDEK(&mlkem768Params, privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

func MLKEM1024WrapDEK(publicKey, dek []byte) ([]byte, error) {
	// Normalize input to raw key bytes (handles raw, SPKI DER, or PEM)
	rawKey, err := normalizeMLKEMPublicKey(publicKey, mlkem1024Params.publicKeySize, mlkem1024Params.oid)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-1024 public key: %w", err)
	}
	return mlkemWrapDEK(&mlkem1024Params, rawKey, dek, defaultTDFSalt(), nil)
}

func MLKEM1024UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return mlkemUnwrapDEK(&mlkem1024Params, privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

// MLKEM768Encapsulate performs ML-KEM-768 encapsulation, returning the shared
// secret and ciphertext without applying KDF or encryption.
func MLKEM768Encapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	return mlkemEncapsulate(&mlkem768Params, publicKeyRaw)
}

// MLKEM1024Encapsulate performs ML-KEM-1024 encapsulation, returning the shared
// secret and ciphertext without applying KDF or encryption.
func MLKEM1024Encapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	return mlkemEncapsulate(&mlkem1024Params, publicKeyRaw)
}

func mlkemEncapsulate(params *mlkemParams, publicKeyRaw []byte) ([]byte, []byte, error) {
	if len(publicKeyRaw) != params.publicKeySize {
		return nil, nil, fmt.Errorf("invalid %s public key size: got %d want %d", params.displayName, len(publicKeyRaw), params.publicKeySize)
	}

	return params.encapsulate(publicKeyRaw)
}

func mlkemWrapDEK(params *mlkemParams, publicKeyRaw, dek, salt, info []byte) ([]byte, error) {
	sharedSecret, ciphertext, err := mlkemEncapsulate(params, publicKeyRaw)
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

func mlkemUnwrapDEK(params *mlkemParams, privateKeyRaw, wrappedDER, salt, info []byte) ([]byte, error) {
	if len(privateKeyRaw) != params.privateKeySize {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", params.displayName, len(privateKeyRaw), params.privateKeySize)
	}

	var wrappedKey MLKEMWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}
	if len(wrappedKey.MLKEMCiphertext) != params.ciphertextSize {
		return nil, fmt.Errorf("invalid %s ciphertext size: got %d want %d", params.displayName, len(wrappedKey.MLKEMCiphertext), params.ciphertextSize)
	}

	dk, err := params.newDecapsulation(privateKeyRaw)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := dk.Decapsulate(wrappedKey.MLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%s decapsulate failed: %w", params.displayName, err)
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
