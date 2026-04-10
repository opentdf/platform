package ocrypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

// X-Wing OID: 1.3.6.1.4.1.62253.25722
// Per draft-connolly-cfrg-xwing-kem-10
var oidXWing = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}

// xwingLabel is the 6-byte ASCII label used in the X-Wing combiner.
// "\./"+"/^\" = 0x5c2e2f2f5e5c
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

const (
	xwingSeedSize       = 32
	xwingExpandedSize   = 96
	xwingPublicKeySize  = 1216 // 1184 (ML-KEM-768 encap key) + 32 (X25519 pub)
	xwingCiphertextSize = 1120 // 1088 (ML-KEM-768 ct) + 32 (X25519 ct)
	xwingSharedKeySize  = 32
	mlkem768EncapSize   = 1184
	mlkem768CTSize      = 1088
	x25519KeySize       = 32
)

// XWingKeyPair holds the 32-byte seed that is the X-Wing decapsulation key.
type XWingKeyPair struct {
	seed [xwingSeedSize]byte
}

// NewXWingKeyPair generates a new X-Wing key pair from a random seed.
func NewXWingKeyPair() (XWingKeyPair, error) {
	var seed [xwingSeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return XWingKeyPair{}, fmt.Errorf("xwing: failed to generate random seed: %w", err)
	}
	return XWingKeyPair{seed: seed}, nil
}

// expandDecapsulationKey derives the component keys from the 32-byte seed.
// Returns (mlkemDecapKey, x25519PrivateKey, mlkemEncapKey, x25519PublicKey).
func expandDecapsulationKey(seed [xwingSeedSize]byte) (*mlkem.DecapsulationKey768, *ecdh.PrivateKey, []byte, []byte, error) {
	// SHAKE256(seed, 96*8) → 96 bytes
	expanded := sha3.SumSHAKE256(seed[:], xwingExpandedSize)

	// d = expanded[0:32], z = expanded[32:64] → ML-KEM-768 seed
	mlkemSeed := expanded[0:64] // d || z
	skM, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("xwing: mlkem.NewDecapsulationKey768 failed: %w", err)
	}
	pkM := skM.EncapsulationKey().Bytes()

	// sk_X = expanded[64:96]
	skX, err := ecdh.X25519().NewPrivateKey(expanded[64:96])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("xwing: X25519 NewPrivateKey failed: %w", err)
	}
	pkX := skX.PublicKey().Bytes()

	return skM, skX, pkM, pkX, nil
}

// xwingCombiner computes SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
func xwingCombiner(ssM, ssX, ctX, pkX []byte) [xwingSharedKeySize]byte {
	var combined []byte
	combined = append(combined, ssM...)
	combined = append(combined, ssX...)
	combined = append(combined, ctX...)
	combined = append(combined, pkX...)
	combined = append(combined, xwingLabel...)
	return sha3.Sum256(combined)
}

// xwingEncapsulate performs X-Wing encapsulation against a 1216-byte public key.
// Returns the 32-byte shared secret and 1120-byte ciphertext.
func xwingEncapsulate(pk []byte) ([xwingSharedKeySize]byte, [xwingCiphertextSize]byte, error) {
	var ss [xwingSharedKeySize]byte
	var ct [xwingCiphertextSize]byte

	if len(pk) != xwingPublicKeySize {
		return ss, ct, fmt.Errorf("xwing: invalid public key size %d, expected %d", len(pk), xwingPublicKeySize)
	}

	pkM := pk[:mlkem768EncapSize]
	pkX := pk[mlkem768EncapSize:]

	// ML-KEM-768 encapsulation
	encapKey, err := mlkem.NewEncapsulationKey768(pkM)
	if err != nil {
		return ss, ct, fmt.Errorf("xwing: mlkem encapsulation key parse failed: %w", err)
	}
	ssM, ctM := encapKey.Encapsulate()

	// X25519 ephemeral key exchange
	ekX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return ss, ct, fmt.Errorf("xwing: X25519 GenerateKey failed: %w", err)
	}
	ctX := ekX.PublicKey().Bytes()

	pkXKey, err := ecdh.X25519().NewPublicKey(pkX)
	if err != nil {
		return ss, ct, fmt.Errorf("xwing: X25519 NewPublicKey failed: %w", err)
	}
	ssX, err := ekX.ECDH(pkXKey)
	if err != nil {
		return ss, ct, fmt.Errorf("xwing: X25519 ECDH failed: %w", err)
	}

	// Combiner
	ss = xwingCombiner(ssM, ssX, ctX, pkX)

	// Ciphertext = ct_M || ct_X
	copy(ct[:mlkem768CTSize], ctM)
	copy(ct[mlkem768CTSize:], ctX)

	return ss, ct, nil
}

// xwingDecapsulate performs X-Wing decapsulation using the 32-byte seed.
func xwingDecapsulate(ct []byte, seed [xwingSeedSize]byte) ([xwingSharedKeySize]byte, error) {
	var ss [xwingSharedKeySize]byte

	if len(ct) != xwingCiphertextSize {
		return ss, fmt.Errorf("xwing: invalid ciphertext size %d, expected %d", len(ct), xwingCiphertextSize)
	}

	skM, skX, _, pkX, err := expandDecapsulationKey(seed)
	if err != nil {
		return ss, err
	}

	ctM := ct[:mlkem768CTSize]
	ctX := ct[mlkem768CTSize:]

	// ML-KEM-768 decapsulation
	ssM, err := skM.Decapsulate(ctM)
	if err != nil {
		return ss, fmt.Errorf("xwing: mlkem decapsulate failed: %w", err)
	}

	// X25519 key exchange with ephemeral ciphertext
	ctXKey, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return ss, fmt.Errorf("xwing: X25519 NewPublicKey(ctX) failed: %w", err)
	}
	ssX, err := skX.ECDH(ctXKey)
	if err != nil {
		return ss, fmt.Errorf("xwing: X25519 ECDH failed: %w", err)
	}

	ss = xwingCombiner(ssM, ssX, ctX, pkX)
	return ss, nil
}

// --- ASN.1 structures for X-Wing key and ciphertext encoding ---

// pkixAlgorithmIdentifier represents an ASN.1 AlgorithmIdentifier.
type pkixAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

// subjectPublicKeyInfo represents ASN.1 SubjectPublicKeyInfo.
type subjectPublicKeyInfo struct {
	Algorithm pkixAlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkcs8PrivateKey represents ASN.1 OneAsymmetricKey / PKCS#8.
type pkcs8PrivateKey struct {
	Version    int
	Algorithm  pkixAlgorithmIdentifier
	PrivateKey []byte
}

// xwingCiphertextASN1 wraps the X-Wing ciphertext with its OID for self-description.
type xwingCiphertextASN1 struct {
	Algorithm  asn1.ObjectIdentifier
	Ciphertext []byte
}

// marshalXWingPublicKey encodes a 1216-byte X-Wing public key as DER SubjectPublicKeyInfo.
func marshalXWingPublicKey(pk []byte) ([]byte, error) {
	spki := subjectPublicKeyInfo{
		Algorithm: pkixAlgorithmIdentifier{Algorithm: oidXWing},
		PublicKey: asn1.BitString{Bytes: pk, BitLength: len(pk) * 8}, //nolint:mnd // bits per byte
	}
	return asn1.Marshal(spki)
}

// marshalXWingPrivateKey encodes a 32-byte X-Wing seed as DER PKCS#8.
func marshalXWingPrivateKey(seed []byte) ([]byte, error) {
	// The privateKey field is an OCTET STRING containing the seed,
	// which itself is DER-encoded as an OCTET STRING.
	innerOctet, err := asn1.Marshal(seed)
	if err != nil {
		return nil, fmt.Errorf("xwing: failed to marshal seed: %w", err)
	}
	pk8 := pkcs8PrivateKey{
		Version:    0,
		Algorithm:  pkixAlgorithmIdentifier{Algorithm: oidXWing},
		PrivateKey: innerOctet,
	}
	return asn1.Marshal(pk8)
}

// marshalXWingCiphertext wraps ciphertext bytes with OID for self-describing encoding.
func marshalXWingCiphertext(ct []byte) ([]byte, error) {
	return asn1.Marshal(xwingCiphertextASN1{
		Algorithm:  oidXWing,
		Ciphertext: ct,
	})
}

// parseXWingCiphertext extracts raw ciphertext from ASN.1 wrapped form.
func parseXWingCiphertext(data []byte) ([]byte, error) {
	var ct xwingCiphertextASN1
	rest, err := asn1.Unmarshal(data, &ct)
	if err != nil {
		return nil, fmt.Errorf("xwing: failed to unmarshal ciphertext ASN.1: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("xwing: trailing data after ciphertext ASN.1")
	}
	if !ct.Algorithm.Equal(oidXWing) {
		return nil, fmt.Errorf("xwing: unexpected OID in ciphertext: %v", ct.Algorithm)
	}
	if len(ct.Ciphertext) != xwingCiphertextSize {
		return nil, fmt.Errorf("xwing: invalid ciphertext size %d in ASN.1", len(ct.Ciphertext))
	}
	return ct.Ciphertext, nil
}

// --- KeyPair interface implementation ---

func (kp XWingKeyPair) GetKeyType() KeyType {
	return HybridXWing
}

func (kp XWingKeyPair) PublicKeyInPemFormat() (string, error) {
	_, _, pkM, pkX, err := expandDecapsulationKey(kp.seed)
	if err != nil {
		return "", err
	}

	pk := make([]byte, 0, xwingPublicKeySize)
	pk = append(pk, pkM...)
	pk = append(pk, pkX...)

	der, err := marshalXWingPublicKey(pk)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), nil
}

func (kp XWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	der, err := marshalXWingPrivateKey(kp.seed[:])
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})), nil
}

// parseXWingPublicKeyFromDER parses a DER-encoded SubjectPublicKeyInfo and returns
// the raw 1216-byte X-Wing public key if the OID matches.
func parseXWingPublicKeyFromDER(der []byte) ([]byte, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("xwing: trailing data after SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(oidXWing) {
		return nil, fmt.Errorf("xwing: unexpected OID: %v", spki.Algorithm.Algorithm)
	}
	pk := spki.PublicKey.Bytes
	if len(pk) != xwingPublicKeySize {
		return nil, fmt.Errorf("xwing: invalid public key size %d", len(pk))
	}
	return pk, nil
}

// parseXWingPrivateKeyFromDER parses a DER-encoded PKCS#8 and returns
// the 32-byte X-Wing seed if the OID matches.
func parseXWingPrivateKeyFromDER(der []byte) ([xwingSeedSize]byte, error) {
	var seed [xwingSeedSize]byte
	var pk8 pkcs8PrivateKey
	rest, err := asn1.Unmarshal(der, &pk8)
	if err != nil {
		return seed, fmt.Errorf("xwing: failed to unmarshal PKCS#8: %w", err)
	}
	if len(rest) > 0 {
		return seed, errors.New("xwing: trailing data after PKCS#8")
	}
	if !pk8.Algorithm.Algorithm.Equal(oidXWing) {
		return seed, fmt.Errorf("xwing: unexpected OID: %v", pk8.Algorithm.Algorithm)
	}

	// The privateKey is a DER-encoded OCTET STRING containing the seed.
	var seedBytes []byte
	_, err = asn1.Unmarshal(pk8.PrivateKey, &seedBytes)
	if err != nil {
		return seed, fmt.Errorf("xwing: failed to unmarshal seed from PKCS#8: %w", err)
	}
	if len(seedBytes) != xwingSeedSize {
		return seed, fmt.Errorf("xwing: invalid seed size %d", len(seedBytes))
	}
	copy(seed[:], seedBytes)
	return seed, nil
}
