package ocrypto

import (
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

// errNotKEM is returned by the generic SPKI / PKCS#8 KEM parsers when the
// supplied DER blob is not a recognised KEM algorithm, signalling the caller
// to fall through to other algorithm parsers.
var errNotKEM = errors.New("not a recognised KEM key")

const (
	MLKEM768PublicKeySize   = 1184 // mlkem768 encapsulation key
	MLKEM768PrivateKeySize  = 64   // mlkem768 seed (d || z)
	MLKEM768CiphertextSize  = 1088 // mlkem768 ciphertext
	MLKEM1024PublicKeySize  = 1568 // mlkem1024 encapsulation key
	MLKEM1024PrivateKeySize = 64   // mlkem1024 seed (d || z)
	MLKEM1024CiphertextSize = 1568 // mlkem1024 ciphertext
)

// NIST-assigned OIDs for ML-KEM (FIPS 203).
var (
	OIDMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	OIDMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

type kemAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type kemSPKI struct {
	Algorithm kemAlgorithmIdentifier
	PublicKey asn1.BitString
}

// kemPKCS8 mirrors RFC 5958 OneAsymmetricKey v1.
type kemPKCS8 struct {
	Version    int
	Algorithm  kemAlgorithmIdentifier
	PrivateKey []byte
}

// marshalKEMPublicSPKI encodes a raw KEM encapsulation key as RFC 5280
// SubjectPublicKeyInfo using the supplied algorithm OID.
func marshalKEMPublicSPKI(oid asn1.ObjectIdentifier, rawKey []byte) ([]byte, error) {
	return asn1.Marshal(kemSPKI{
		Algorithm: kemAlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: rawKey, BitLength: len(rawKey) * bitsPerByte},
	})
}

// marshalKEMPrivatePKCS8 encodes a raw KEM seed (or private key) as RFC 5958
// OneAsymmetricKey, with the inner KEM-PrivateKey CHOICE selected as [0]
// IMPLICIT OCTET STRING.
func marshalKEMPrivatePKCS8(oid asn1.ObjectIdentifier, rawSeedOrKey []byte) ([]byte, error) {
	inner, err := asn1.MarshalWithParams(rawSeedOrKey, "tag:0,implicit")
	if err != nil {
		return nil, fmt.Errorf("asn1.MarshalWithParams seed failed: %w", err)
	}
	return asn1.Marshal(kemPKCS8{
		Version:    0,
		Algorithm:  kemAlgorithmIdentifier{Algorithm: oid},
		PrivateKey: inner,
	})
}

// ParseKEMPublicSPKI returns the OID and raw encapsulation key bytes from any
// SPKI DER blob whose AlgorithmIdentifier has no parameters. If the blob is
// not a well-formed parameter-less SPKI structure the sentinel errNotKEM is
// returned so the caller can fall through to other parsers.
func ParseKEMPublicSPKI(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var s kemSPKI
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil || len(rest) != 0 {
		return nil, nil, errNotKEM
	}
	if s.PublicKey.BitLength%bitsPerByte != 0 {
		return nil, nil, errors.New("KEM SPKI bit string is not byte-aligned")
	}
	return s.Algorithm.Algorithm, s.PublicKey.RightAlign(), nil
}

// ParseMLKEMPublicSPKI returns the OID and raw encapsulation key bytes from an
// SPKI DER blob if the algorithm is ML-KEM-768 or ML-KEM-1024.
//
// Deprecated: Use ParseKEMPublicSPKI and verify the returned OID against the
// expected ML-KEM variant.
func ParseMLKEMPublicSPKI(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	oid, raw, err := ParseKEMPublicSPKI(der)
	if err != nil {
		return nil, nil, err
	}
	if !oid.Equal(OIDMLKEM768) && !oid.Equal(OIDMLKEM1024) {
		return nil, nil, errNotKEM
	}
	return oid, raw, nil
}

// parseKEMPrivatePKCS8 returns the OID and raw seed bytes from any PKCS#8 DER
// blob whose AlgorithmIdentifier matches a registered KEM scheme and whose
// inner private key is encoded as [0] IMPLICIT OCTET STRING. The sentinel
// errNotKEM is returned for any non-KEM PKCS#8 blob so the caller can fall
// through to other parsers.
func parseKEMPrivatePKCS8(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var p kemPKCS8
	rest, err := asn1.Unmarshal(der, &p)
	if err != nil || len(rest) != 0 {
		return nil, nil, errNotKEM
	}
	if _, ok := kemRegistry[p.Algorithm.Algorithm.String()]; !ok {
		return nil, nil, errNotKEM
	}

	var innerSeed []byte
	innerRest, err := asn1.UnmarshalWithParams(p.PrivateKey, &innerSeed, "tag:0,implicit")
	if err != nil || len(innerRest) != 0 {
		return nil, nil, fmt.Errorf("KEM PKCS#8 inner seed parse failed: %w", err)
	}
	return p.Algorithm.Algorithm, innerSeed, nil
}

// normalizeMLKEMPublicKey detects the input format and returns raw key bytes.
// Accepts: raw key (1184/1568 bytes), SPKI DER (1206/1590 bytes), or PEM-wrapped SPKI.
func normalizeMLKEMPublicKey(input []byte, expectedRawSize int, expectedOID asn1.ObjectIdentifier) ([]byte, error) {
	if len(input) == expectedRawSize {
		return input, nil
	}

	if block, _ := pem.Decode(input); block != nil {
		if block.Type != pemBlockPublicKey {
			return nil, fmt.Errorf("expected %s PEM block, got %s", pemBlockPublicKey, block.Type)
		}
		input = block.Bytes
	}

	oid, rawKey, err := ParseMLKEMPublicSPKI(input)
	if err != nil {
		if errors.Is(err, errNotKEM) {
			return nil, errors.New("not an ML-KEM key in SPKI format")
		}
		return nil, fmt.Errorf("failed to parse SPKI: %w", err)
	}

	if !oid.Equal(expectedOID) {
		return nil, fmt.Errorf("OID mismatch: expected %v, got %v", expectedOID, oid)
	}

	if len(rawKey) != expectedRawSize {
		return nil, fmt.Errorf("extracted key has wrong size: got %d want %d", len(rawKey), expectedRawSize)
	}

	return rawKey, nil
}

// MLKEM768WrapDEK encapsulates against an ML-KEM-768 public key (raw, SPKI
// DER, or PEM) and returns the ASN.1 DER envelope carrying the KEM ciphertext
// and AES-GCM-wrapped DEK. The ML-KEM Decaps shared secret is used directly
// as the AES-256 wrap key (no HKDF); see adr/decisions/2026-06-16-mlkem-direct-key-wrap.md.
//
// Deprecated: Use WrapDEK with MLKEM768Key, or construct via FromPublicPEM.
func MLKEM768WrapDEK(publicKey, dek []byte) ([]byte, error) {
	rawKey, err := normalizeMLKEMPublicKey(publicKey, MLKEM768PublicKeySize, OIDMLKEM768)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 public key: %w", err)
	}
	return wrapDEKWithKEM(mlkemKEM{variant: mlkem768}, rawKey, dek, nil, nil)
}

// MLKEM768UnwrapDEK decapsulates the envelope produced by MLKEM768WrapDEK
// using the supplied raw ML-KEM-768 seed. This is the binary-bytes counterpart
// to FromPrivatePEM; callers that already hold a raw seed can use it directly
// without re-encoding to PKCS#8 PEM.
func MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return unwrapDEKWithKEM(mlkemKEM{variant: mlkem768}, privateKeyRaw, wrappedDER, nil, nil)
}

// MLKEM1024WrapDEK encapsulates against an ML-KEM-1024 public key (raw, SPKI
// DER, or PEM) and returns the ASN.1 DER envelope carrying the KEM ciphertext
// and AES-GCM-wrapped DEK. The ML-KEM Decaps shared secret is used directly
// as the AES-256 wrap key (no HKDF); see adr/decisions/2026-06-16-mlkem-direct-key-wrap.md.
//
// Deprecated: Use WrapDEK with MLKEM1024Key, or construct via FromPublicPEM.
func MLKEM1024WrapDEK(publicKey, dek []byte) ([]byte, error) {
	rawKey, err := normalizeMLKEMPublicKey(publicKey, MLKEM1024PublicKeySize, OIDMLKEM1024)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-1024 public key: %w", err)
	}
	return wrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, rawKey, dek, nil, nil)
}

// MLKEM1024UnwrapDEK decapsulates the envelope produced by MLKEM1024WrapDEK
// using the supplied raw ML-KEM-1024 seed. This is the binary-bytes counterpart
// to FromPrivatePEM; callers that already hold a raw seed can use it directly
// without re-encoding to PKCS#8 PEM.
func MLKEM1024UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return unwrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, privateKeyRaw, wrappedDER, nil, nil)
}
