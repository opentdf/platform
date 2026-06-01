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

// PEM block types defined by RFC 7468 for SPKI / PKCS#8 envelopes.
const (
	pemBlockPublicKey  = "PUBLIC KEY"
	pemBlockPrivateKey = "PRIVATE KEY"
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
	OidMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	OidMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
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
	case s.Algorithm.Algorithm.Equal(OidMLKEM768):
		oid = OidMLKEM768
	case s.Algorithm.Algorithm.Equal(OidMLKEM1024):
		oid = OidMLKEM1024
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
	case p.Algorithm.Algorithm.Equal(OidMLKEM768):
		oid = OidMLKEM768
	case p.Algorithm.Algorithm.Equal(OidMLKEM1024):
		oid = OidMLKEM1024
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
	der, err := marshalMLKEMPublicSPKI(OidMLKEM768, e.publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal ML-KEM-768 SPKI failed: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
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
	der, err := marshalMLKEMPublicSPKI(OidMLKEM1024, e.publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal ML-KEM-1024 SPKI failed: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
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
		if block.Type != pemBlockPublicKey {
			return nil, fmt.Errorf("expected %s PEM block, got %s", pemBlockPublicKey, block.Type)
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
	rawKey, err := normalizeMLKEMPublicKey(publicKey, MLKEM768PublicKeySize, OidMLKEM768)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 public key: %w", err)
	}
	return mlkem768WrapDEK(rawKey, dek, defaultTDFSalt(), nil)
}

func MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return mlkem768UnwrapDEK(privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

func MLKEM1024WrapDEK(publicKey, dek []byte) ([]byte, error) {
	// Normalize input to raw key bytes (handles raw, SPKI DER, or PEM)
	rawKey, err := normalizeMLKEMPublicKey(publicKey, MLKEM1024PublicKeySize, OidMLKEM1024)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-1024 public key: %w", err)
	}
	return mlkem1024WrapDEK(rawKey, dek, defaultTDFSalt(), nil)
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
