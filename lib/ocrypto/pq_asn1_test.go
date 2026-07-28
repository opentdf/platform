package ocrypto

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestMarshalParseHybridSPKI_RoundTrip(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 59}
	raw := bytes.Repeat([]byte{0xAB}, 1249)

	der, err := marshalHybridSPKI(oid, raw)
	if err != nil {
		t.Fatalf("marshalHybridSPKI: %v", err)
	}

	gotOID, gotRaw, err := parseHybridSPKI(der)
	if err != nil {
		t.Fatalf("parseHybridSPKI: %v", err)
	}
	if !gotOID.Equal(oid) {
		t.Fatalf("OID mismatch: got %v want %v", gotOID, oid)
	}
	if !bytes.Equal(gotRaw, raw) {
		t.Fatalf("raw mismatch")
	}
}

func TestMarshalParseHybridPKCS8_RoundTrip(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}
	raw := bytes.Repeat([]byte{0xCD}, 96)

	der, err := marshalHybridPKCS8(oid, raw)
	if err != nil {
		t.Fatalf("marshalHybridPKCS8: %v", err)
	}

	gotOID, gotRaw, err := parseHybridPKCS8(der)
	if err != nil {
		t.Fatalf("parseHybridPKCS8: %v", err)
	}
	if !gotOID.Equal(oid) {
		t.Fatalf("OID mismatch: got %v want %v", gotOID, oid)
	}
	if !bytes.Equal(gotRaw, raw) {
		t.Fatalf("raw mismatch")
	}
}

func TestParseHybridSPKI_TrailingBytes(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 59}
	der, err := marshalHybridSPKI(oid, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("marshalHybridSPKI: %v", err)
	}
	der = append(der, 0x00)
	if _, _, err := parseHybridSPKI(der); err == nil {
		t.Fatalf("expected trailing-bytes error")
	}
}

func TestParseHybridPKCS8_Version(t *testing.T) {
	// Hand-built PKCS#8 with version=1 should be rejected.
	pkcs8 := oneAsymmetricKey{
		Version:    1,
		Algorithm:  pkixAlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}},
		PrivateKey: []byte{0xAA},
	}
	der, err := asn1.Marshal(pkcs8)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	if _, _, err := parseHybridPKCS8(der); err == nil {
		t.Fatalf("expected version error")
	}
}
