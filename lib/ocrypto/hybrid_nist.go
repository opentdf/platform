package ocrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

const (
	P256PrivateScalarSize = 32
	P256PublicPointSize   = 65
	P384PrivateScalarSize = 48
	P384PublicPointSize   = 97
	AES256KeySize         = 32

	P256MLKEM768PrivateKeySize  = P256PrivateScalarSize + mlkem768.PrivateKeySize
	P256MLKEM768PublicKeySize   = P256PublicPointSize + mlkem768.PublicKeySize
	P256MLKEM768CiphertextSize  = P256PublicPointSize + mlkem768.CiphertextSize
	P256MLKEM768SharedKeySize   = P256PrivateScalarSize + mlkem768.SharedKeySize
	P384MLKEM1024PrivateKeySize = P384PrivateScalarSize + mlkem1024.PrivateKeySize
	P384MLKEM1024PublicKeySize  = P384PublicPointSize + mlkem1024.PublicKeySize
	P384MLKEM1024CiphertextSize = P384PublicPointSize + mlkem1024.CiphertextSize
	P384MLKEM1024SharedKeySize  = P384PrivateScalarSize + mlkem1024.SharedKeySize

	PEMBlockP256MLKEM768PublicKey   = "SECP256R1 MLKEM768 PUBLIC KEY"
	PEMBlockP256MLKEM768PrivateKey  = "SECP256R1 MLKEM768 PRIVATE KEY"
	PEMBlockP384MLKEM1024PublicKey  = "SECP384R1 MLKEM1024 PUBLIC KEY"
	PEMBlockP384MLKEM1024PrivateKey = "SECP384R1 MLKEM1024 PRIVATE KEY"
)

type HybridWrappedKey struct {
	HybridCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK     []byte `asn1:"tag:1"`
}

type hybridECMLKEMParams struct {
	name           string
	keyType        KeyType
	curve          ecdh.Curve
	ecPrivateSize  int
	ecPublicSize   int
	publicKeySize  int
	privateKeySize int
	ciphertextSize int
	sharedKeySize  int
	publicPEMType  string
	privatePEMType string
	mlkemScheme    kem.Scheme
}

type HybridECMLKEMKeyPair struct {
	params     hybridECMLKEMParams
	publicKey  []byte
	privateKey []byte
}

type HybridECMLKEMEncryptor struct {
	params    hybridECMLKEMParams
	publicKey []byte
	salt      []byte
	info      []byte
}

type HybridECMLKEMDecryptor struct {
	params     hybridECMLKEMParams
	privateKey []byte
	salt       []byte
	info       []byte
}

var (
	p256MLKEM768Params = hybridECMLKEMParams{
		name:           "SecP256r1/ML-KEM-768",
		keyType:        HybridSecp256r1MLKEM768Key,
		curve:          ecdh.P256(),
		ecPrivateSize:  P256PrivateScalarSize,
		ecPublicSize:   P256PublicPointSize,
		publicKeySize:  P256MLKEM768PublicKeySize,
		privateKeySize: P256MLKEM768PrivateKeySize,
		ciphertextSize: P256MLKEM768CiphertextSize,
		sharedKeySize:  P256MLKEM768SharedKeySize,
		publicPEMType:  PEMBlockP256MLKEM768PublicKey,
		privatePEMType: PEMBlockP256MLKEM768PrivateKey,
		mlkemScheme:    mlkem768.Scheme(),
	}
	p384MLKEM1024Params = hybridECMLKEMParams{
		name:           "SecP384r1/ML-KEM-1024",
		keyType:        HybridSecp384r1MLKEM1024Key,
		curve:          ecdh.P384(),
		ecPrivateSize:  P384PrivateScalarSize,
		ecPublicSize:   P384PublicPointSize,
		publicKeySize:  P384MLKEM1024PublicKeySize,
		privateKeySize: P384MLKEM1024PrivateKeySize,
		ciphertextSize: P384MLKEM1024CiphertextSize,
		sharedKeySize:  P384MLKEM1024SharedKeySize,
		publicPEMType:  PEMBlockP384MLKEM1024PublicKey,
		privatePEMType: PEMBlockP384MLKEM1024PrivateKey,
		mlkemScheme:    mlkem1024.Scheme(),
	}
)

func NewP256MLKEM768KeyPair() (HybridECMLKEMKeyPair, error) {
	return newHybridECMLKEMKeyPair(p256MLKEM768Params)
}

func NewP384MLKEM1024KeyPair() (HybridECMLKEMKeyPair, error) {
	return newHybridECMLKEMKeyPair(p384MLKEM1024Params)
}

func (k HybridECMLKEMKeyPair) PublicKeyInPemFormat() (string, error) {
	return xwingRawToPEM(k.params.publicPEMType, k.publicKey, k.params.publicKeySize)
}

func (k HybridECMLKEMKeyPair) PrivateKeyInPemFormat() (string, error) {
	return xwingRawToPEM(k.params.privatePEMType, k.privateKey, k.params.privateKeySize)
}

func (k HybridECMLKEMKeyPair) GetKeyType() KeyType {
	return k.params.keyType
}

func P256MLKEM768PubKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP256MLKEM768PublicKey, P256MLKEM768PublicKeySize)
}

func P256MLKEM768PrivateKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP256MLKEM768PrivateKey, P256MLKEM768PrivateKeySize)
}

func P384MLKEM1024PubKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP384MLKEM1024PublicKey, P384MLKEM1024PublicKeySize)
}

func P384MLKEM1024PrivateKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP384MLKEM1024PrivateKey, P384MLKEM1024PrivateKeySize)
}

func NewP256MLKEM768Encryptor(publicKey, salt, info []byte) (*HybridECMLKEMEncryptor, error) {
	return newHybridECMLKEMEncryptor(p256MLKEM768Params, publicKey, salt, info)
}

func NewP384MLKEM1024Encryptor(publicKey, salt, info []byte) (*HybridECMLKEMEncryptor, error) {
	return newHybridECMLKEMEncryptor(p384MLKEM1024Params, publicKey, salt, info)
}

func (e *HybridECMLKEMEncryptor) Encrypt(data []byte) ([]byte, error) {
	return hybridWrapDEK(e.params, e.publicKey, data, e.salt, e.info)
}

func (e *HybridECMLKEMEncryptor) PublicKeyInPemFormat() (string, error) {
	return xwingRawToPEM(e.params.publicPEMType, e.publicKey, e.params.publicKeySize)
}

func (e *HybridECMLKEMEncryptor) Type() SchemeType {
	return Hybrid
}

func (e *HybridECMLKEMEncryptor) KeyType() KeyType {
	return e.params.keyType
}

func (e *HybridECMLKEMEncryptor) EphemeralKey() []byte {
	return nil
}

func (e *HybridECMLKEMEncryptor) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func NewP256MLKEM768Decryptor(privateKey []byte) (*HybridECMLKEMDecryptor, error) {
	return newSaltedHybridECMLKEMDecryptor(p256MLKEM768Params, privateKey, defaultXWingSalt(), nil)
}

func NewP384MLKEM1024Decryptor(privateKey []byte) (*HybridECMLKEMDecryptor, error) {
	return newSaltedHybridECMLKEMDecryptor(p384MLKEM1024Params, privateKey, defaultXWingSalt(), nil)
}

func (d *HybridECMLKEMDecryptor) Decrypt(data []byte) ([]byte, error) {
	return hybridUnwrapDEK(d.params, d.privateKey, data, d.salt, d.info)
}

func P256MLKEM768WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return hybridWrapDEK(p256MLKEM768Params, publicKeyRaw, dek, defaultXWingSalt(), nil)
}

func P256MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return hybridUnwrapDEK(p256MLKEM768Params, privateKeyRaw, wrappedDER, defaultXWingSalt(), nil)
}

func P384MLKEM1024WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return hybridWrapDEK(p384MLKEM1024Params, publicKeyRaw, dek, defaultXWingSalt(), nil)
}

func P384MLKEM1024UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return hybridUnwrapDEK(p384MLKEM1024Params, privateKeyRaw, wrappedDER, defaultXWingSalt(), nil)
}

func newHybridECMLKEMKeyPair(params hybridECMLKEMParams) (HybridECMLKEMKeyPair, error) {
	ecPrivateKey, err := params.curve.GenerateKey(rand.Reader)
	if err != nil {
		return HybridECMLKEMKeyPair{}, fmt.Errorf("%s ECDH key generation failed: %w", params.name, err)
	}

	mlkemPublicKey, mlkemPrivateKey, err := params.mlkemScheme.GenerateKeyPair()
	if err != nil {
		return HybridECMLKEMKeyPair{}, fmt.Errorf("%s ML-KEM key generation failed: %w", params.name, err)
	}

	mlkemPublicKeyRaw, err := mlkemPublicKey.MarshalBinary()
	if err != nil {
		return HybridECMLKEMKeyPair{}, fmt.Errorf("%s ML-KEM public key marshal failed: %w", params.name, err)
	}
	mlkemPrivateKeyRaw, err := mlkemPrivateKey.MarshalBinary()
	if err != nil {
		return HybridECMLKEMKeyPair{}, fmt.Errorf("%s ML-KEM private key marshal failed: %w", params.name, err)
	}

	publicKey := append(append(make([]byte, 0, params.publicKeySize), ecPrivateKey.PublicKey().Bytes()...), mlkemPublicKeyRaw...)
	privateKey := append(append(make([]byte, 0, params.privateKeySize), ecPrivateKey.Bytes()...), mlkemPrivateKeyRaw...)
	if len(publicKey) != params.publicKeySize {
		return HybridECMLKEMKeyPair{}, fmt.Errorf("%s invalid public key size: got %d want %d", params.name, len(publicKey), params.publicKeySize)
	}
	if len(privateKey) != params.privateKeySize {
		return HybridECMLKEMKeyPair{}, fmt.Errorf("%s invalid private key size: got %d want %d", params.name, len(privateKey), params.privateKeySize)
	}

	return HybridECMLKEMKeyPair{
		params:     params,
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func newHybridECMLKEMEncryptor(params hybridECMLKEMParams, publicKey, salt, info []byte) (*HybridECMLKEMEncryptor, error) {
	if len(publicKey) != params.publicKeySize {
		return nil, fmt.Errorf("invalid %s public key size: got %d want %d", params.name, len(publicKey), params.publicKeySize)
	}

	return &HybridECMLKEMEncryptor{
		params:    params,
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
	}, nil
}

func newSaltedHybridECMLKEMDecryptor(params hybridECMLKEMParams, privateKey, salt, info []byte) (*HybridECMLKEMDecryptor, error) {
	if len(privateKey) != params.privateKeySize {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", params.name, len(privateKey), params.privateKeySize)
	}

	return &HybridECMLKEMDecryptor{
		params:     params,
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
	}, nil
}

func hybridWrapDEK(params hybridECMLKEMParams, publicKeyRaw, dek, salt, info []byte) ([]byte, error) {
	ecPublicKey, mlkemPublicKey, err := parseHybridPublicKey(params, publicKeyRaw)
	if err != nil {
		return nil, err
	}

	ecEphemeralKey, err := params.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s ECDH encapsulation key generation failed: %w", params.name, err)
	}

	ecSharedSecret, err := ecEphemeralKey.ECDH(ecPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s ECDH encapsulation failed: %w", params.name, err)
	}

	mlkemCiphertext, mlkemSharedSecret, err := params.mlkemScheme.Encapsulate(mlkemPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s ML-KEM encapsulate failed: %w", params.name, err)
	}

	hybridSharedSecret := append(append(make([]byte, 0, len(ecSharedSecret)+len(mlkemSharedSecret)), ecSharedSecret...), mlkemSharedSecret...)
	wrapKey, err := deriveHybridWrapKey(params, hybridSharedSecret, salt, info)
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

	hybridCiphertext := append(append(make([]byte, 0, params.ciphertextSize), ecEphemeralKey.PublicKey().Bytes()...), mlkemCiphertext...)
	if len(hybridCiphertext) != params.ciphertextSize {
		return nil, fmt.Errorf("%s invalid ciphertext size: got %d want %d", params.name, len(hybridCiphertext), params.ciphertextSize)
	}

	wrappedDER, err := asn1.Marshal(HybridWrappedKey{
		HybridCiphertext: hybridCiphertext,
		EncryptedDEK:     encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return wrappedDER, nil
}

func hybridUnwrapDEK(params hybridECMLKEMParams, privateKeyRaw, wrappedDER, salt, info []byte) ([]byte, error) {
	ecPrivateKey, mlkemPrivateKey, err := parseHybridPrivateKey(params, privateKeyRaw)
	if err != nil {
		return nil, err
	}

	var wrappedKey HybridWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}
	if len(wrappedKey.HybridCiphertext) != params.ciphertextSize {
		return nil, fmt.Errorf("invalid %s ciphertext size: got %d want %d", params.name, len(wrappedKey.HybridCiphertext), params.ciphertextSize)
	}

	ephemeralPublicKeyRaw := wrappedKey.HybridCiphertext[:params.ecPublicSize]
	mlkemCiphertext := wrappedKey.HybridCiphertext[params.ecPublicSize:]

	ephemeralPublicKey, err := params.curve.NewPublicKey(ephemeralPublicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("%s ephemeral public key parse failed: %w", params.name, err)
	}

	ecSharedSecret, err := ecPrivateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s ECDH decapsulation failed: %w", params.name, err)
	}

	mlkemSharedSecret, err := params.mlkemScheme.Decapsulate(mlkemPrivateKey, mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%s ML-KEM decapsulate failed: %w", params.name, err)
	}

	hybridSharedSecret := append(append(make([]byte, 0, len(ecSharedSecret)+len(mlkemSharedSecret)), ecSharedSecret...), mlkemSharedSecret...)
	wrapKey, err := deriveHybridWrapKey(params, hybridSharedSecret, salt, info)
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

func deriveHybridWrapKey(params hybridECMLKEMParams, sharedSecret, salt, info []byte) ([]byte, error) {
	if len(sharedSecret) != params.sharedKeySize {
		return nil, fmt.Errorf("invalid %s shared secret size: got %d want %d", params.name, len(sharedSecret), params.sharedKeySize)
	}
	if len(salt) == 0 {
		salt = defaultXWingSalt()
	}

	hkdfObj := hkdf.New(sha256.New, sharedSecret, salt, info)
	derivedKey := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	return derivedKey, nil
}

func parseHybridPublicKey(params hybridECMLKEMParams, publicKeyRaw []byte) (*ecdh.PublicKey, kem.PublicKey, error) {
	if len(publicKeyRaw) != params.publicKeySize {
		return nil, nil, fmt.Errorf("invalid %s public key size: got %d want %d", params.name, len(publicKeyRaw), params.publicKeySize)
	}

	ecPublicKey, err := params.curve.NewPublicKey(publicKeyRaw[:params.ecPublicSize])
	if err != nil {
		return nil, nil, fmt.Errorf("%s ECDH public key parse failed: %w", params.name, err)
	}

	mlkemPublicKey, err := params.mlkemScheme.UnmarshalBinaryPublicKey(publicKeyRaw[params.ecPublicSize:])
	if err != nil {
		return nil, nil, fmt.Errorf("%s ML-KEM public key parse failed: %w", params.name, err)
	}

	return ecPublicKey, mlkemPublicKey, nil
}

func parseHybridPrivateKey(params hybridECMLKEMParams, privateKeyRaw []byte) (*ecdh.PrivateKey, kem.PrivateKey, error) {
	if len(privateKeyRaw) != params.privateKeySize {
		return nil, nil, fmt.Errorf("invalid %s private key size: got %d want %d", params.name, len(privateKeyRaw), params.privateKeySize)
	}

	ecPrivateKey, err := params.curve.NewPrivateKey(privateKeyRaw[:params.ecPrivateSize])
	if err != nil {
		return nil, nil, fmt.Errorf("%s ECDH private key parse failed: %w", params.name, err)
	}

	mlkemPrivateKey, err := params.mlkemScheme.UnmarshalBinaryPrivateKey(privateKeyRaw[params.ecPrivateSize:])
	if err != nil {
		return nil, nil, fmt.Errorf("%s ML-KEM private key parse failed: %w", params.name, err)
	}

	return ecPrivateKey, mlkemPrivateKey, nil
}

func hybridParamsFromPublicPEMType(blockType string) (hybridECMLKEMParams, bool) {
	switch blockType {
	case PEMBlockP256MLKEM768PublicKey:
		return p256MLKEM768Params, true
	case PEMBlockP384MLKEM1024PublicKey:
		return p384MLKEM1024Params, true
	default:
		return hybridECMLKEMParams{}, false
	}
}

func hybridParamsFromPrivatePEMType(blockType string) (hybridECMLKEMParams, bool) {
	switch blockType {
	case PEMBlockP256MLKEM768PrivateKey:
		return p256MLKEM768Params, true
	case PEMBlockP384MLKEM1024PrivateKey:
		return p384MLKEM1024Params, true
	default:
		return hybridECMLKEMParams{}, false
	}
}
