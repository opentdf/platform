package ocrypto

import (
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
)

// errNotKEM is returned by the generic SPKI / PKCS#8 KEM parsers when the
// supplied DER blob is not a recognised KEM algorithm, signalling the caller
// to fall through to other algorithm parsers.
var errNotKEM = errors.New("not a recognised KEM key")

const (
	MLKEM768PublicKeySize    = 1184 // mlkem768 encapsulation key
	MLKEM768PrivateKeySize   = 64   // mlkem768 seed (d || z)
	MLKEM768ExpandedKeySize  = 2400
	MLKEM768CiphertextSize   = 1088 // mlkem768 ciphertext
	MLKEM1024PublicKeySize   = 1568 // mlkem1024 encapsulation key
	MLKEM1024PrivateKeySize  = 64   // mlkem1024 seed (d || z)
	MLKEM1024ExpandedKeySize = 3168
	MLKEM1024CiphertextSize  = 1568 // mlkem1024 ciphertext
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

// parseKEMPrivatePKCS8 returns the OID and seed or expanded private key from a
// registered pure ML-KEM PKCS#8 key. For the both form it validates the pair
// and returns the seed. Other algorithms return errNotKEM for routing.
func parseKEMPrivatePKCS8(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var outer asn1.RawValue
	outerRest, err := asn1.Unmarshal(der, &outer)
	if err != nil || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, nil, errNotKEM
	}
	var version int
	rest, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil {
		return nil, nil, errNotKEM
	}
	var algorithm asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &algorithm)
	if err != nil || algorithm.Class != asn1.ClassUniversal || algorithm.Tag != asn1.TagSequence || !algorithm.IsCompound {
		return nil, nil, errNotKEM
	}
	var oid asn1.ObjectIdentifier
	algorithmRest, err := asn1.Unmarshal(algorithm.Bytes, &oid)
	if err != nil {
		return nil, nil, errNotKEM
	}
	m, ok := kemByOID(oid)
	if !ok {
		return nil, nil, errNotKEM
	}
	if len(outerRest) != 0 || len(algorithmRest) != 0 {
		return nil, nil, errors.New("ML-KEM PKCS#8 has trailing bytes or algorithm parameters")
	}
	if version != 0 {
		return nil, nil, fmt.Errorf("ML-KEM PKCS#8 version %d: want 0", version)
	}
	var privateKey []byte
	rest, err = asn1.Unmarshal(rest, &privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM PKCS#8 privateKey parse failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("ML-KEM PKCS#8 has extra fields")
	}
	key, ok := m.(mlkemKEM)
	if !ok {
		return nil, nil, errNotKEM
	}
	var inner asn1.RawValue
	innerRest, err := asn1.Unmarshal(privateKey, &inner)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM private key CHOICE parse failed: %w", err)
	}
	if len(innerRest) != 0 {
		return nil, nil, errors.New("ML-KEM private key CHOICE parse failed: trailing bytes")
	}
	var raw []byte
	switch {
	case inner.Class == asn1.ClassContextSpecific && inner.Tag == 0 && !inner.IsCompound:
		raw = inner.Bytes
		if len(raw) != key.privSize() {
			return nil, nil, fmt.Errorf("ML-KEM seed length: got %d want %d", len(raw), key.privSize())
		}
	case inner.Class == asn1.ClassUniversal && inner.Tag == asn1.TagOctetString && !inner.IsCompound:
		raw = inner.Bytes
		if len(raw) != key.expandedSize() {
			return nil, nil, fmt.Errorf("ML-KEM expandedKey length: got %d want %d", len(raw), key.expandedSize())
		}
		if err := key.validateExpanded(raw); err != nil {
			return nil, nil, fmt.Errorf("ML-KEM expandedKey invalid: %w", err)
		}
	case inner.Class == asn1.ClassUniversal && inner.Tag == asn1.TagSequence && inner.IsCompound:
		var seed, expanded []byte
		bothRest, err := asn1.Unmarshal(inner.Bytes, &seed)
		if err != nil {
			return nil, nil, fmt.Errorf("ML-KEM both seed parse failed: %w", err)
		}
		bothRest, err = asn1.Unmarshal(bothRest, &expanded)
		if err != nil {
			return nil, nil, fmt.Errorf("ML-KEM both parse failed: %w", err)
		}
		if len(bothRest) != 0 {
			return nil, nil, errors.New("ML-KEM both parse failed: extra fields")
		}
		if len(seed) != key.privSize() {
			return nil, nil, fmt.Errorf("ML-KEM both seed length: got %d want %d", len(seed), key.privSize())
		}
		if len(expanded) != key.expandedSize() {
			return nil, nil, fmt.Errorf("ML-KEM both expandedKey length: got %d want %d", len(expanded), key.expandedSize())
		}
		expected, err := key.expandSeed(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("ML-KEM both validation failed: %w", err)
		}
		if subtle.ConstantTimeCompare(expected, expanded) != 1 {
			return nil, nil, errors.New("ML-KEM both seed and expandedKey disagree")
		}
		raw = seed
	default:
		return nil, nil, fmt.Errorf("ML-KEM private key CHOICE invalid tag: class %d tag %d compound %t", inner.Class, inner.Tag, inner.IsCompound)
	}
	return oid, raw, nil
}
