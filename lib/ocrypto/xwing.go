package ocrypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/xwing"
)

const (
	HybridXWingKey KeyType = "hpqt:xwing"

	XWingPublicKeySize  = xwing.PublicKeySize
	XWingPrivateKeySize = xwing.PrivateKeySize
	XWingCiphertextSize = xwing.CiphertextSize

	PEMBlockXWingPublicKey  = "XWING PUBLIC KEY"
	PEMBlockXWingPrivateKey = "XWING PRIVATE KEY"
)

type XWingKeyPair struct {
	publicKey  []byte
	privateKey []byte
}

func NewXWingKeyPair() (XWingKeyPair, error) {
	sk, pk, err := xwing.GenerateKeyPair(rand.Reader)
	if err != nil {
		return XWingKeyPair{}, fmt.Errorf("xwing.GenerateKeyPair failed: %w", err)
	}

	publicKey := make([]byte, XWingPublicKeySize)
	privateKey := make([]byte, XWingPrivateKeySize)
	pk.Pack(publicKey)
	sk.Pack(privateKey)

	return XWingKeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func (k XWingKeyPair) PublicKeyInPemFormat() (string, error) {
	return rawToPEM(PEMBlockXWingPublicKey, k.publicKey, XWingPublicKeySize)
}

func (k XWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	return rawToPEM(PEMBlockXWingPrivateKey, k.privateKey, XWingPrivateKeySize)
}

func (k XWingKeyPair) GetKeyType() KeyType {
	return HybridXWingKey
}

func XWingPubKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockXWingPublicKey, XWingPublicKeySize)
}

func XWingPrivateKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockXWingPrivateKey, XWingPrivateKeySize)
}

// XWingWrapDEK encapsulates against an X-Wing public key and returns the
// ASN.1 DER envelope carrying the KEM ciphertext and AES-GCM-wrapped DEK.
//
// Deprecated: Use WrapDEK with HybridXWingKey, or construct via FromPublicPEM.
func XWingWrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return wrapDEKWithKEM(xwingKEM{}, publicKeyRaw, dek, defaultTDFSalt(), nil)
}

// XWingUnwrapDEK decapsulates the envelope produced by XWingWrapDEK using the
// supplied raw X-Wing private key. This is the binary-bytes counterpart to
// FromPrivatePEM (which works from PEM); callers that already hold raw key
// material can use it directly without re-encoding to PEM.
func XWingUnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return unwrapDEKWithKEM(xwingKEM{}, privateKeyRaw, wrappedDER, defaultTDFSalt(), nil)
}
