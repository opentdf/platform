package ocrypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

const (
	HybridSecp256r1MLKEM768Key  KeyType = "hpqt:secp256r1-mlkem768"
	HybridSecp384r1MLKEM1024Key KeyType = "hpqt:secp384r1-mlkem1024"
)

// ML-KEM seed size (d || z) used by crypto/mlkem for private key serialization.
const mlkemSeedSize = 64

// Sizes for P-256 + ML-KEM-768 hybrid.
const (
	P256MLKEM768ECPublicKeySize  = 65   // uncompressed P-256 point
	P256MLKEM768ECPrivateKeySize = 32   // P-256 scalar
	P256MLKEM768MLKEMPubKeySize  = 1184 // mlkem768 encapsulation key
	P256MLKEM768MLKEMPrivKeySize = mlkemSeedSize
	P256MLKEM768MLKEMCtSize      = 1088 // mlkem768 ciphertext

	P256MLKEM768PublicKeySize  = P256MLKEM768ECPublicKeySize + P256MLKEM768MLKEMPubKeySize   // 1249
	P256MLKEM768PrivateKeySize = P256MLKEM768ECPrivateKeySize + P256MLKEM768MLKEMPrivKeySize // 96
	P256MLKEM768CiphertextSize = P256MLKEM768ECPublicKeySize + P256MLKEM768MLKEMCtSize       // 1153

	PEMBlockP256MLKEM768PublicKey  = "SECP256R1 MLKEM768 PUBLIC KEY"
	PEMBlockP256MLKEM768PrivateKey = "SECP256R1 MLKEM768 PRIVATE KEY"
)

// Sizes for P-384 + ML-KEM-1024 hybrid.
const (
	P384MLKEM1024ECPublicKeySize  = 97   // uncompressed P-384 point
	P384MLKEM1024ECPrivateKeySize = 48   // P-384 scalar
	P384MLKEM1024MLKEMPubKeySize  = 1568 // mlkem1024 encapsulation key
	P384MLKEM1024MLKEMPrivKeySize = mlkemSeedSize
	P384MLKEM1024MLKEMCtSize      = 1568 // mlkem1024 ciphertext

	P384MLKEM1024PublicKeySize  = P384MLKEM1024ECPublicKeySize + P384MLKEM1024MLKEMPubKeySize   // 1665
	P384MLKEM1024PrivateKeySize = P384MLKEM1024ECPrivateKeySize + P384MLKEM1024MLKEMPrivKeySize // 112
	P384MLKEM1024CiphertextSize = P384MLKEM1024ECPublicKeySize + P384MLKEM1024MLKEMCtSize       // 1665

	PEMBlockP384MLKEM1024PublicKey  = "SECP384R1 MLKEM1024 PUBLIC KEY"
	PEMBlockP384MLKEM1024PrivateKey = "SECP384R1 MLKEM1024 PRIVATE KEY"
)

// hybridNISTParams captures the curve-specific parameters for a NIST hybrid scheme.
type hybridNISTParams struct {
	curve         ecdh.Curve
	ecPubSize     int
	ecPrivSize    int
	mlkemPubSize  int
	mlkemPrivSize int
	mlkemCtSize   int
	pubPEMBlock   string
	privPEMBlock  string
	keyType       KeyType
}

var p256mlkem768Params = hybridNISTParams{
	curve:         ecdh.P256(),
	ecPubSize:     P256MLKEM768ECPublicKeySize,
	ecPrivSize:    P256MLKEM768ECPrivateKeySize,
	mlkemPubSize:  P256MLKEM768MLKEMPubKeySize,
	mlkemPrivSize: P256MLKEM768MLKEMPrivKeySize,
	mlkemCtSize:   P256MLKEM768MLKEMCtSize,
	pubPEMBlock:   PEMBlockP256MLKEM768PublicKey,
	privPEMBlock:  PEMBlockP256MLKEM768PrivateKey,
	keyType:       HybridSecp256r1MLKEM768Key,
}

var p384mlkem1024Params = hybridNISTParams{
	curve:         ecdh.P384(),
	ecPubSize:     P384MLKEM1024ECPublicKeySize,
	ecPrivSize:    P384MLKEM1024ECPrivateKeySize,
	mlkemPubSize:  P384MLKEM1024MLKEMPubKeySize,
	mlkemPrivSize: P384MLKEM1024MLKEMPrivKeySize,
	mlkemCtSize:   P384MLKEM1024MLKEMCtSize,
	pubPEMBlock:   PEMBlockP384MLKEM1024PublicKey,
	privPEMBlock:  PEMBlockP384MLKEM1024PrivateKey,
	keyType:       HybridSecp384r1MLKEM1024Key,
}

// HybridNISTKeyPair holds a hybrid EC + ML-KEM keypair as raw bytes.
type HybridNISTKeyPair struct {
	publicKey  []byte
	privateKey []byte
	params     *hybridNISTParams
}

// IsHybridKeyType returns true if the key type is a hybrid post-quantum type.
func IsHybridKeyType(kt KeyType) bool {
	switch kt { //nolint:exhaustive // only handle hybrid types
	case HybridXWingKey, HybridSecp256r1MLKEM768Key, HybridSecp384r1MLKEM1024Key:
		return true
	default:
		return false
	}
}

// NewHybridKeyPair creates a key pair for the given hybrid key type.
func NewHybridKeyPair(kt KeyType) (KeyPair, error) {
	switch kt { //nolint:exhaustive // only handle hybrid types
	case HybridXWingKey:
		return NewXWingKeyPair()
	case HybridSecp256r1MLKEM768Key:
		return NewP256MLKEM768KeyPair()
	case HybridSecp384r1MLKEM1024Key:
		return NewP384MLKEM1024KeyPair()
	default:
		return nil, fmt.Errorf("unsupported hybrid key type: %v", kt)
	}
}

func NewP256MLKEM768KeyPair() (HybridNISTKeyPair, error) {
	return newHybridNISTKeyPair(&p256mlkem768Params, func() ([]byte, []byte, error) {
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	})
}

func NewP384MLKEM1024KeyPair() (HybridNISTKeyPair, error) {
	return newHybridNISTKeyPair(&p384mlkem1024Params, func() ([]byte, []byte, error) {
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	})
}

func newHybridNISTKeyPair(p *hybridNISTParams, genMLKEM func() (pub, priv []byte, err error)) (HybridNISTKeyPair, error) {
	ecPriv, err := p.curve.GenerateKey(rand.Reader)
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("ECDH key generation failed: %w", err)
	}
	ecPub := ecPriv.PublicKey().Bytes() // uncompressed point
	ecPrivBytes := ecPriv.Bytes()       // raw scalar

	mlkemPub, mlkemPriv, err := genMLKEM()
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("ML-KEM key generation failed: %w", err)
	}

	pubKey := make([]byte, 0, p.ecPubSize+p.mlkemPubSize)
	pubKey = append(pubKey, ecPub...)
	pubKey = append(pubKey, mlkemPub...)

	privKey := make([]byte, 0, p.ecPrivSize+p.mlkemPrivSize)
	privKey = append(privKey, ecPrivBytes...)
	privKey = append(privKey, mlkemPriv...)

	return HybridNISTKeyPair{
		publicKey:  pubKey,
		privateKey: privKey,
		params:     p,
	}, nil
}

func (k HybridNISTKeyPair) PublicKeyInPemFormat() (string, error) {
	return rawToPEM(k.params.pubPEMBlock, k.publicKey, k.params.ecPubSize+k.params.mlkemPubSize)
}

func (k HybridNISTKeyPair) PrivateKeyInPemFormat() (string, error) {
	return rawToPEM(k.params.privPEMBlock, k.privateKey, k.params.ecPrivSize+k.params.mlkemPrivSize)
}

func (k HybridNISTKeyPair) GetKeyType() KeyType {
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

// P256MLKEM768WrapDEK wraps a DEK using the P-256 + ML-KEM-768 hybrid scheme.
//
// Deprecated: Use WrapDEK with HybridSecp256r1MLKEM768Key, or construct via
// FromPublicPEM.
func P256MLKEM768WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return wrapDEKWithKEM(nistHybridKEM{params: &p256mlkem768Params}, publicKeyRaw, dek, defaultTDFSalt(), nil)
}

// P256MLKEM768UnwrapDEK unwraps an envelope produced by P256MLKEM768WrapDEK
// using the supplied raw P-256 + ML-KEM-768 private key. This is the binary-
// bytes counterpart to FromPrivatePEM; callers that already hold raw key
// material can use it directly without re-encoding to PEM.
func P256MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return unwrapDEKWithKEM(nistHybridKEM{params: &p256mlkem768Params}, privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}

// P384MLKEM1024WrapDEK wraps a DEK using the P-384 + ML-KEM-1024 hybrid scheme.
//
// Deprecated: Use WrapDEK with HybridSecp384r1MLKEM1024Key, or construct via
// FromPublicPEM.
func P384MLKEM1024WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return wrapDEKWithKEM(nistHybridKEM{params: &p384mlkem1024Params}, publicKeyRaw, dek, defaultTDFSalt(), nil)
}

// P384MLKEM1024UnwrapDEK unwraps an envelope produced by P384MLKEM1024WrapDEK
// using the supplied raw P-384 + ML-KEM-1024 private key. This is the binary-
// bytes counterpart to FromPrivatePEM; callers that already hold raw key
// material can use it directly without re-encoding to PEM.
func P384MLKEM1024UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return unwrapDEKWithKEM(nistHybridKEM{params: &p384mlkem1024Params}, privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}
