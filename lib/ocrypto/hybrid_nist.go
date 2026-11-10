package ocrypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

const (
	HybridSecp256r1MLKEM768Key  KeyType = "hpqt:secp256r1-mlkem768"
	HybridSecp384r1MLKEM1024Key KeyType = "hpqt:secp384r1-mlkem1024"
)

// ML-KEM seed size (d || z) used by crypto/mlkem for private key serialization.
const mlkemSeedSize = 64

// Sizes for the elementary halves of the two NIST composite-KEM hybrids.
const (
	P256MLKEM768ECPublicKeySize = 65 // uncompressed P-256 point (RFC 5480)
	P256MLKEM768MLKEMSeedSize   = mlkemSeedSize
	P256MLKEM768MLKEMPubKeySize = 1184
	P256MLKEM768MLKEMCtSize     = 1088

	P384MLKEM1024ECPublicKeySize = 97 // uncompressed P-384 point (RFC 5480)
	P384MLKEM1024MLKEMSeedSize   = mlkemSeedSize
	P384MLKEM1024MLKEMPubKeySize = 1568
	P384MLKEM1024MLKEMCtSize     = 1568

	// Concatenated sizes: public key (draft-14 §4.1) and ciphertext (§4.3),
	// both laid out as `mlkem || ec`.
	P256MLKEM768PublicKeySize   = P256MLKEM768MLKEMPubKeySize + P256MLKEM768ECPublicKeySize   // 1249
	P256MLKEM768CiphertextSize  = P256MLKEM768MLKEMCtSize + P256MLKEM768ECPublicKeySize       // 1153
	P384MLKEM1024PublicKeySize  = P384MLKEM1024MLKEMPubKeySize + P384MLKEM1024ECPublicKeySize // 1665
	P384MLKEM1024CiphertextSize = P384MLKEM1024MLKEMCtSize + P384MLKEM1024ECPublicKeySize     // 1665
)

// hybridNISTParams captures the curve-specific parameters for one composite-KEM
// hybrid scheme.
type hybridNISTParams struct {
	curve        ecdh.Curve     // for ECDH shared secret
	namedCurve   elliptic.Curve // for x509.MarshalECPrivateKey / RFC 5915
	ecPubSize    int            // uncompressed point length
	mlkemPubSize int
	mlkemCtSize  int
	label        string                // ASCII domain-separator per draft-14 §6
	oid          asn1.ObjectIdentifier // AlgorithmIdentifier OID (draft-14 §6)
	keyType      KeyType
}

// p256mlkem768Params and p384mlkem1024Params MUST stay structurally identical
// (same field set, same field order). If you add a field, add it to BOTH; if
// a third NIST composite-KEM hybrid lands, prefer consolidating these into a
// `map[asn1.ObjectIdentifier]hybridNISTParams` at that point.
var p256mlkem768Params = hybridNISTParams{
	curve:        ecdh.P256(),
	namedCurve:   elliptic.P256(),
	ecPubSize:    P256MLKEM768ECPublicKeySize,
	mlkemPubSize: P256MLKEM768MLKEMPubKeySize,
	mlkemCtSize:  P256MLKEM768MLKEMCtSize,
	label:        labelMLKEM768P256,
	oid:          oidCompositeMLKEM768P256,
	keyType:      HybridSecp256r1MLKEM768Key,
}

var p384mlkem1024Params = hybridNISTParams{
	curve:        ecdh.P384(),
	namedCurve:   elliptic.P384(),
	ecPubSize:    P384MLKEM1024ECPublicKeySize,
	mlkemPubSize: P384MLKEM1024MLKEMPubKeySize,
	mlkemCtSize:  P384MLKEM1024MLKEMCtSize,
	label:        labelMLKEM1024P384,
	oid:          oidCompositeMLKEM1024P384,
	keyType:      HybridSecp384r1MLKEM1024Key,
}

// HybridNISTKeyPair holds the raw byte form of a composite-KEM keypair:
//   - publicKey  = mlkemEncapsulationKey || uncompressedECPoint
//   - privateKey = mlkemSeed             || ECPrivateKey(DER, RFC 5915)
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
	return newHybridNISTKeyPair(&p256mlkem768Params, generateMLKEM768)
}

func NewP384MLKEM1024KeyPair() (HybridNISTKeyPair, error) {
	return newHybridNISTKeyPair(&p384mlkem1024Params, generateMLKEM1024)
}

func generateMLKEM768() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

func generateMLKEM1024() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

func newHybridNISTKeyPair(p *hybridNISTParams, genMLKEM func() ([]byte, []byte, error)) (HybridNISTKeyPair, error) {
	ecPriv, err := ecdsa.GenerateKey(p.namedCurve, rand.Reader)
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("EC key generation failed: %w", err)
	}
	ecPrivDER, err := x509.MarshalECPrivateKey(ecPriv)
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("encode ECPrivateKey: %w", err)
	}
	ecdhPriv, err := ecPriv.ECDH()
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("convert ECDSA to ECDH: %w", err)
	}
	ecPub := ecdhPriv.PublicKey().Bytes()

	mlkemPub, mlkemSeed, err := genMLKEM()
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("ML-KEM key generation failed: %w", err)
	}

	pubKey := make([]byte, 0, len(mlkemPub)+len(ecPub))
	pubKey = append(pubKey, mlkemPub...)
	pubKey = append(pubKey, ecPub...)

	privKey := make([]byte, 0, len(mlkemSeed)+len(ecPrivDER))
	privKey = append(privKey, mlkemSeed...)
	privKey = append(privKey, ecPrivDER...)

	return HybridNISTKeyPair{
		publicKey:  pubKey,
		privateKey: privKey,
		params:     p,
	}, nil
}

func (k HybridNISTKeyPair) PublicKeyInPemFormat() (string, error) {
	der, err := marshalHybridSPKI(k.params.oid, k.publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
}

func (k HybridNISTKeyPair) PrivateKeyInPemFormat() (string, error) {
	der, err := marshalHybridPKCS8(k.params.oid, k.privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: der})), nil
}

func (k HybridNISTKeyPair) GetKeyType() KeyType {
	return k.params.keyType
}

// hybridNISTKEM adapts a NIST composite-KEM hybrid (EC + ML-KEM) onto the
// shared kem interface so it flows through wrapDEKWithKEM / unwrapDEKWithKEM
// and the single kemEnvelope wire format. The combiner that produces the
// AES-256 wrap key is folded into encapsulate / decapsulate, so wrapKey is an
// identity pass-through of the already-derived key (mirroring pure ML-KEM).
type hybridNISTKEM struct {
	params *hybridNISTParams
}

func (k hybridNISTKEM) keyType() KeyType { return k.params.keyType }
func (hybridNISTKEM) scheme() SchemeType { return Hybrid }
func (k hybridNISTKEM) pubSize() int     { return k.params.mlkemPubSize + k.params.ecPubSize }
func (k hybridNISTKEM) ctSize() int      { return k.params.mlkemCtSize + k.params.ecPubSize }

// privSize is negative to mark a variable-length private key encoding
// (mlkemSeed || ECPrivateKey DER, whose length depends on the RFC 5915
// serialization). newKEMDecryptor skips its exact-size check for this scheme;
// decapsulate validates the layout instead.
func (hybridNISTKEM) privSize() int { return -1 }

// encapsulate performs ECDH against an ephemeral key, ML-KEM encapsulation, and
// the SHA3-256 combiner (draft-ietf-lamps-pq-composite-kem-14 §3.4), returning
// the 32-byte combined key as the "shared secret" and `mlkemCT || ephemeralEC`
// as the ciphertext. Math is preserved verbatim from the former
// hybridNISTWrapDEK.
func (k hybridNISTKEM) encapsulate(publicKeyRaw []byte) ([]byte, []byte, error) {
	p := k.params
	expectedPubSize := p.mlkemPubSize + p.ecPubSize
	if len(publicKeyRaw) != expectedPubSize {
		return nil, nil, fmt.Errorf("invalid %s public key size: got %d want %d", p.keyType, len(publicKeyRaw), expectedPubSize)
	}

	mlkemPubBytes := publicKeyRaw[:p.mlkemPubSize]
	ecPubBytes := publicKeyRaw[p.mlkemPubSize:]

	ecPub, err := p.curve.NewPublicKey(ecPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid EC public key: %w", err)
	}
	ephemeral, err := p.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH ephemeral key generation failed: %w", err)
	}
	tradSS, err := ephemeral.ECDH(ecPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	mlkemSS, mlkemCT, err := mlkemEncapsulate(p, mlkemPubBytes)
	if err != nil {
		return nil, nil, err
	}

	wrapKey := hybridNISTCombiner(p, mlkemSS, tradSS, ephemeralPub, ecPubBytes)

	hybridCt := make([]byte, 0, len(mlkemCT)+len(ephemeralPub))
	hybridCt = append(hybridCt, mlkemCT...)
	hybridCt = append(hybridCt, ephemeralPub...)

	return wrapKey, hybridCt, nil
}

// decapsulate is the symmetric inverse of encapsulate, returning the combiner
// output as the "shared secret". Math is preserved verbatim from the former
// hybridNISTUnwrapDEK. The ciphertext length is validated by unwrapDEKWithKEM
// against ctSize() before this is called.
func (k hybridNISTKEM) decapsulate(privateKeyRaw, ct []byte) ([]byte, error) {
	p := k.params
	if len(privateKeyRaw) <= mlkemSeedSize {
		return nil, fmt.Errorf("invalid %s private key: shorter than ML-KEM seed + ECPrivateKey", p.keyType)
	}
	mlkemSeed := privateKeyRaw[:mlkemSeedSize]
	ecPrivDER := privateKeyRaw[mlkemSeedSize:]

	mlkemCT := ct[:p.mlkemCtSize]
	ephemeralPubBytes := ct[p.mlkemCtSize:]

	ecdsaPriv, err := x509.ParseECPrivateKey(ecPrivDER)
	if err != nil {
		return nil, fmt.Errorf("parse ECPrivateKey: %w", err)
	}
	if ecdsaPriv.Curve != p.namedCurve {
		return nil, fmt.Errorf("EC private key curve mismatch for %s", p.keyType)
	}
	ecdhPriv, err := ecdsaPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert ECDSA to ECDH: %w", err)
	}
	tradPK := ecdhPriv.PublicKey().Bytes()

	ephemeralPub, err := p.curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral EC public key: %w", err)
	}
	tradSS, err := ecdhPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// ML-KEM implicit rejection (FIPS 203 §6.3) yields a pseudorandom shared
	// secret on a wrong-key ciphertext rather than an error here; the AES-GCM
	// decrypt in unwrapDEKWithKEM provides authentication.
	mlkemSS, err := mlkemDecapsulate(p, mlkemSeed, mlkemCT)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate failed: %w", err)
	}

	return hybridNISTCombiner(p, mlkemSS, tradSS, ephemeralPubBytes, tradPK), nil
}

func (k hybridNISTKEM) publicKeyPEM(pub []byte) (string, error) {
	der, err := marshalHybridSPKI(k.params.oid, pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
}

// wrapKey is an identity pass-through: encapsulate / decapsulate already ran the
// SHA3-256 combiner, which emits the 32-byte AES-256 key directly (no extra KDF
// per draft-14 §3.4). The length check guards against a combiner change.
func (hybridNISTKEM) wrapKey(sharedSecret, _ /*salt*/, _ /*info*/ []byte) ([]byte, error) {
	if len(sharedSecret) != kemWrapKeySize {
		return nil, fmt.Errorf("invalid hybrid NIST wrap key size: got %d want %d", len(sharedSecret), kemWrapKeySize)
	}
	return append([]byte(nil), sharedSecret...), nil
}

// hybridNISTCombiner returns the 32-byte SHA3-256 digest defined in
// draft-ietf-lamps-pq-composite-kem-14 §3.4:
//
//	SS = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)
//
// The 32-byte output is used directly as the AES-256 wrap key for our DEK
// envelope (no additional KDF step, per the draft).
//
// Input lengths are invariants of the call sites (hybridNISTWrapDEK /
// hybridNISTUnwrapDEK). A mismatch here means a programming bug, not bad
// user input — panicking is preferable to silently producing a
// wrong-but-valid-looking wrap key.
func hybridNISTCombiner(p *hybridNISTParams, mlkemSS, tradSS, tradCT, tradPK []byte) []byte {
	const sec1UncompressedHalves = 2 // SEC1 uncompressed point = 0x04 || x || y (two equal halves)
	expectedTradSS := (p.ecPubSize - 1) / sec1UncompressedHalves
	if len(mlkemSS) != mlkem.SharedKeySize {
		panic(fmt.Sprintf("hybridNISTCombiner: mlkemSS length %d, want %d", len(mlkemSS), mlkem.SharedKeySize))
	}
	if len(tradSS) != expectedTradSS {
		panic(fmt.Sprintf("hybridNISTCombiner[%s]: tradSS length %d, want %d", p.keyType, len(tradSS), expectedTradSS))
	}
	if len(tradCT) != p.ecPubSize {
		panic(fmt.Sprintf("hybridNISTCombiner[%s]: tradCT length %d, want %d", p.keyType, len(tradCT), p.ecPubSize))
	}
	if len(tradPK) != p.ecPubSize {
		panic(fmt.Sprintf("hybridNISTCombiner[%s]: tradPK length %d, want %d", p.keyType, len(tradPK), p.ecPubSize))
	}
	h := sha3.New256()
	// hash.Hash.Write never returns an error (documented in the stdlib).
	_, _ = h.Write(mlkemSS)
	_, _ = h.Write(tradSS)
	_, _ = h.Write(tradCT)
	_, _ = h.Write(tradPK)
	_, _ = h.Write([]byte(p.label))
	return h.Sum(nil)
}

func mlkemEncapsulate(p *hybridNISTParams, mlkemPubBytes []byte) ([]byte, []byte, error) {
	switch p.keyType { //nolint:exhaustive // only NIST hybrid types
	case HybridSecp256r1MLKEM768Key:
		ek, err := mlkem.NewEncapsulationKey768(mlkemPubBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem768 encapsulation key: %w", err)
		}
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	case HybridSecp384r1MLKEM1024Key:
		ek, err := mlkem.NewEncapsulationKey1024(mlkemPubBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem1024 encapsulation key: %w", err)
		}
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	default:
		return nil, nil, fmt.Errorf("unsupported ML-KEM key type: %s", p.keyType)
	}
}

func mlkemDecapsulate(p *hybridNISTParams, mlkemSeed, mlkemCT []byte) ([]byte, error) {
	switch p.keyType { //nolint:exhaustive // only NIST hybrid types
	case HybridSecp256r1MLKEM768Key:
		dk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
		if err != nil {
			return nil, fmt.Errorf("mlkem768 decapsulation key: %w", err)
		}
		return dk.Decapsulate(mlkemCT)
	case HybridSecp384r1MLKEM1024Key:
		dk, err := mlkem.NewDecapsulationKey1024(mlkemSeed)
		if err != nil {
			return nil, fmt.Errorf("mlkem1024 decapsulation key: %w", err)
		}
		return dk.Decapsulate(mlkemCT)
	default:
		return nil, fmt.Errorf("unsupported ML-KEM key type: %s", p.keyType)
	}
}
