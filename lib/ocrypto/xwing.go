package ocrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

const (
	HybridXWingKey KeyType = "hpqt:xwing"

	XWingPublicKeySize  = xwing.PublicKeySize
	XWingPrivateKeySize = xwing.PrivateKeySize
	XWingCiphertextSize = xwing.CiphertextSize
)

// X-Wing wire-format note:
//
// The KEM primitive comes from github.com/cloudflare/circl/kem/xwing, which
// currently implements draft-connolly-cfrg-xwing-kem-05. The SPKI/PKCS#8
// envelope and AlgorithmIdentifier OID (id-XWing, draft-10 §5.8) follow
// draft-10. The two drafts differ in the internal labeling/KDF chain of the
// KEM itself, so wrapped keys produced here are NOT wire-compatible with a
// pure draft-10 implementation.
//
// TODO(DSPX-TBD): swap the primitive to a draft-10 implementation once one
// is available in Go (tracking: upgrade cloudflare/circl xwing to draft-10).

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
	der, err := marshalHybridSPKI(oidXWing, k.publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
}

func (k XWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	der, err := marshalHybridPKCS8(oidXWing, k.privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: der})), nil
}

func (k XWingKeyPair) GetKeyType() KeyType {
	return HybridXWingKey
}

// xwingKEM adapts the X-Wing KEM onto the shared kem interface so it flows
// through wrapDEKWithKEM / unwrapDEKWithKEM and the single kemEnvelope wire
// format, alongside pure ML-KEM and the NIST composite hybrids.
type xwingKEM struct{}

func (xwingKEM) keyType() KeyType   { return HybridXWingKey }
func (xwingKEM) scheme() SchemeType { return Hybrid }
func (xwingKEM) pubSize() int       { return XWingPublicKeySize }
func (xwingKEM) privSize() int      { return XWingPrivateKeySize }
func (xwingKEM) ctSize() int        { return XWingCiphertextSize }

func (xwingKEM) encapsulate(pub []byte) ([]byte, []byte, error) {
	return XWingEncapsulate(pub)
}

func (xwingKEM) decapsulate(priv, ct []byte) ([]byte, error) {
	return xwing.Decapsulate(ct, priv), nil
}

func (xwingKEM) publicKeyPEM(pub []byte) (string, error) {
	der, err := marshalHybridSPKI(oidXWing, pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
}

// wrapKey derives the AES-256 wrap key from the X-Wing shared secret via
// HKDF-SHA256 over (salt, info), per the hybrid PQ/T combiner-hygiene contract.
func (xwingKEM) wrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	return deriveXWingWrapKey(sharedSecret, salt, info)
}

// XWingEncapsulate performs the X-Wing KEM encapsulation, returning the shared
// secret and ciphertext without applying KDF or encryption.
func XWingEncapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	if len(publicKeyRaw) != XWingPublicKeySize {
		return nil, nil, fmt.Errorf("invalid X-Wing public key size: got %d want %d", len(publicKeyRaw), XWingPublicKeySize)
	}

	sharedSecret, ciphertext, err := xwing.Encapsulate(publicKeyRaw, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing.Encapsulate failed: %w", err)
	}

	return sharedSecret, ciphertext, nil
}

func deriveXWingWrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = defaultTDFSalt()
	}

	hkdfObj := hkdf.New(sha256.New, sharedSecret, salt, info)
	derivedKey := make([]byte, xwing.SharedKeySize)
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	return derivedKey, nil
}
