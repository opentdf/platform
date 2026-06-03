package ocrypto

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

const bitsPerByte = 8

// pkixAlgorithmIdentifier matches the structure used by the SPKI/PKCS#8 envelopes
// in RFC 5280 and RFC 5958. For the hybrid PQ/T schemes covered here the
// parameters field is always absent, so it is modelled as an optional RawValue.
type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm        pkixAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// oneAsymmetricKey is the RFC 5958 PKCS#8 structure. Only v1 (Version = 0) with
// no attributes or publicKey is used here.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkixAlgorithmIdentifier
	PrivateKey []byte
}

// marshalHybridSPKI wraps a raw hybrid public key in a SubjectPublicKeyInfo
// whose AlgorithmIdentifier carries the supplied OID with no parameters.
func marshalHybridSPKI(oid asn1.ObjectIdentifier, raw []byte) ([]byte, error) {
	spki := subjectPublicKeyInfo{
		Algorithm: pkixAlgorithmIdentifier{Algorithm: oid},
		SubjectPublicKey: asn1.BitString{
			Bytes:     raw,
			BitLength: len(raw) * bitsPerByte,
		},
	}
	der, err := asn1.Marshal(spki)
	if err != nil {
		return nil, fmt.Errorf("marshal SPKI: %w", err)
	}
	return der, nil
}

// parseHybridSPKI returns the AlgorithmIdentifier OID and the raw BIT STRING
// payload of a hybrid SubjectPublicKeyInfo. It does not validate the OID — the
// caller decides whether the OID is one it understands.
func parseHybridSPKI(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SPKI: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("parse SPKI: %d trailing bytes", len(rest))
	}
	if spki.SubjectPublicKey.BitLength != len(spki.SubjectPublicKey.Bytes)*bitsPerByte {
		return nil, nil, errors.New("parse SPKI: unexpected unused bits in BIT STRING")
	}
	return spki.Algorithm.Algorithm, spki.SubjectPublicKey.Bytes, nil
}

// marshalHybridPKCS8 wraps a raw hybrid private key in a PKCS#8 OneAsymmetricKey
// envelope (v1) whose AlgorithmIdentifier carries the supplied OID with no
// parameters.
func marshalHybridPKCS8(oid asn1.ObjectIdentifier, raw []byte) ([]byte, error) {
	pkcs8 := oneAsymmetricKey{
		Version:    0,
		Algorithm:  pkixAlgorithmIdentifier{Algorithm: oid},
		PrivateKey: raw,
	}
	der, err := asn1.Marshal(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return der, nil
}

// parseHybridPKCS8 returns the AlgorithmIdentifier OID and the raw OCTET STRING
// payload of a hybrid PKCS#8 OneAsymmetricKey envelope.
func parseHybridPKCS8(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var pkcs8 oneAsymmetricKey
	rest, err := asn1.Unmarshal(der, &pkcs8)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("parse PKCS#8: %d trailing bytes", len(rest))
	}
	if pkcs8.Version != 0 {
		return nil, nil, fmt.Errorf("parse PKCS#8: unsupported version %d", pkcs8.Version)
	}
	return pkcs8.Algorithm.Algorithm, pkcs8.PrivateKey, nil
}
