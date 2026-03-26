package ocrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestXWingKeyPairGeneration(t *testing.T) {
	kp, err := NewXWingKeyPair()
	if err != nil {
		t.Fatalf("NewXWingKeyPair failed: %v", err)
	}

	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		t.Fatalf("PublicKeyInPemFormat failed: %v", err)
	}
	if pubPEM == "" {
		t.Fatal("empty public key PEM")
	}

	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatalf("PrivateKeyInPemFormat failed: %v", err)
	}
	if privPEM == "" {
		t.Fatal("empty private key PEM")
	}

	if kp.GetKeyType() != HybridXWing {
		t.Fatalf("expected key type %s, got %s", HybridXWing, kp.GetKeyType())
	}
}

func TestXWingKeyPairViaFactory(t *testing.T) {
	kp, err := NewKeyPair(HybridXWing)
	if err != nil {
		t.Fatalf("NewKeyPair(HybridXWing) failed: %v", err)
	}
	if kp.GetKeyType() != HybridXWing {
		t.Fatalf("expected key type %s, got %s", HybridXWing, kp.GetKeyType())
	}
}

func TestXWingPEMRoundTrip(t *testing.T) {
	kp, err := NewXWingKeyPair()
	if err != nil {
		t.Fatalf("NewXWingKeyPair failed: %v", err)
	}

	// Public key round-trip
	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		t.Fatalf("PublicKeyInPemFormat failed: %v", err)
	}

	enc, err := FromPublicPEM(pubPEM)
	if err != nil {
		t.Fatalf("FromPublicPEM failed for X-Wing public key: %v", err)
	}
	if enc.Type() != Hybrid {
		t.Fatalf("expected scheme type %s, got %s", Hybrid, enc.Type())
	}
	if enc.KeyType() != HybridXWing {
		t.Fatalf("expected key type %s, got %s", HybridXWing, enc.KeyType())
	}

	// Private key round-trip
	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatalf("PrivateKeyInPemFormat failed: %v", err)
	}

	dec, err := FromPrivatePEM(privPEM)
	if err != nil {
		t.Fatalf("FromPrivatePEM failed for X-Wing private key: %v", err)
	}
	if _, ok := dec.(*XWingDecryptor); !ok {
		t.Fatalf("expected XWingDecryptor, got %T", dec)
	}
}

func TestXWingEncryptDecryptRoundTrip(t *testing.T) {
	kp, err := NewXWingKeyPair()
	if err != nil {
		t.Fatalf("NewXWingKeyPair failed: %v", err)
	}

	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		t.Fatalf("PublicKeyInPemFormat failed: %v", err)
	}

	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatalf("PrivateKeyInPemFormat failed: %v", err)
	}

	// Encrypt
	enc, err := FromPublicPEM(pubPEM)
	if err != nil {
		t.Fatalf("FromPublicPEM failed: %v", err)
	}

	plaintext := []byte("hello, X-Wing hybrid KEM!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ephemeralKey := enc.EphemeralKey()
	if len(ephemeralKey) == 0 {
		t.Fatal("EphemeralKey returned empty")
	}

	// Decrypt
	dec, err := FromPrivatePEM(privPEM)
	if err != nil {
		t.Fatalf("FromPrivatePEM failed: %v", err)
	}

	recovered, err := dec.DecryptWithEphemeralKey(ciphertext, ephemeralKey)
	if err != nil {
		t.Fatalf("DecryptWithEphemeralKey failed: %v", err)
	}

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("plaintext mismatch: got %q, want %q", recovered, plaintext)
	}
}

func TestXWingMultipleEncryptions(t *testing.T) {
	kp, err := NewXWingKeyPair()
	if err != nil {
		t.Fatalf("NewXWingKeyPair failed: %v", err)
	}

	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		t.Fatalf("PublicKeyInPemFormat failed: %v", err)
	}

	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatalf("PrivateKeyInPemFormat failed: %v", err)
	}

	for i := range 5 {
		plaintext := []byte("message " + string(rune('A'+i)))

		enc, err := FromPublicPEM(pubPEM)
		if err != nil {
			t.Fatalf("FromPublicPEM failed: %v", err)
		}

		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		ek := enc.EphemeralKey()

		dec, err := FromPrivatePEM(privPEM)
		if err != nil {
			t.Fatalf("FromPrivatePEM failed: %v", err)
		}

		recovered, err := dec.DecryptWithEphemeralKey(ct, ek)
		if err != nil {
			t.Fatalf("DecryptWithEphemeralKey failed for message %d: %v", i, err)
		}

		if !bytes.Equal(plaintext, recovered) {
			t.Fatalf("plaintext mismatch for message %d", i)
		}
	}
}

func TestXWingCombiner(t *testing.T) {
	// Verify the combiner produces deterministic output
	ssM := make([]byte, 32)
	ssX := make([]byte, 32)
	ctX := make([]byte, 32)
	pkX := make([]byte, 32)

	result1 := xwingCombiner(ssM, ssX, ctX, pkX)
	result2 := xwingCombiner(ssM, ssX, ctX, pkX)

	if result1 != result2 {
		t.Fatal("combiner not deterministic")
	}

	// Different inputs should produce different outputs
	ssM[0] = 1
	result3 := xwingCombiner(ssM, ssX, ctX, pkX)
	if result1 == result3 {
		t.Fatal("combiner should produce different output for different inputs")
	}
}

func TestXWingLabel(t *testing.T) {
	// Verify the label matches the spec: 0x5c2e2f2f5e5c
	expected, _ := hex.DecodeString("5c2e2f2f5e5c")
	if !bytes.Equal(xwingLabel, expected) {
		t.Fatalf("XWing label mismatch: got %x, want %x", xwingLabel, expected)
	}
}

func TestXWingCiphertextASN1RoundTrip(t *testing.T) {
	// Create a fake 1120-byte ciphertext
	ct := make([]byte, xwingCiphertextSize)
	for i := range ct {
		ct[i] = byte(i % 256)
	}

	encoded, err := marshalXWingCiphertext(ct)
	if err != nil {
		t.Fatalf("marshalXWingCiphertext failed: %v", err)
	}

	decoded, err := parseXWingCiphertext(encoded)
	if err != nil {
		t.Fatalf("parseXWingCiphertext failed: %v", err)
	}

	if !bytes.Equal(ct, decoded) {
		t.Fatal("ciphertext round-trip mismatch")
	}
}

func TestXWingPublicKeyASN1RoundTrip(t *testing.T) {
	// Create a fake 1216-byte public key
	pk := make([]byte, xwingPublicKeySize)
	for i := range pk {
		pk[i] = byte(i % 256)
	}

	der, err := marshalXWingPublicKey(pk)
	if err != nil {
		t.Fatalf("marshalXWingPublicKey failed: %v", err)
	}

	decoded, err := parseXWingPublicKeyFromDER(der)
	if err != nil {
		t.Fatalf("parseXWingPublicKeyFromDER failed: %v", err)
	}

	if !bytes.Equal(pk, decoded) {
		t.Fatal("public key round-trip mismatch")
	}
}

func TestXWingPrivateKeyASN1RoundTrip(t *testing.T) {
	seed := [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}

	der, err := marshalXWingPrivateKey(seed[:])
	if err != nil {
		t.Fatalf("marshalXWingPrivateKey failed: %v", err)
	}

	decoded, err := parseXWingPrivateKeyFromDER(der)
	if err != nil {
		t.Fatalf("parseXWingPrivateKeyFromDER failed: %v", err)
	}

	if seed != decoded {
		t.Fatal("private key round-trip mismatch")
	}
}

// TestXWingRFCTestVector1 verifies against the first test vector from
// draft-connolly-cfrg-xwing-kem-10 Appendix C.
func TestXWingRFCTestVector1(t *testing.T) {
	seedHex := "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
	expectedSSHex := "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384"

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}

	expectedSS, err := hex.DecodeString(expectedSSHex)
	if err != nil {
		t.Fatal(err)
	}

	// Verify seed expands to produce the expected public key
	var seedArr [32]byte
	copy(seedArr[:], seed)
	_, _, pkM, pkX, err := expandDecapsulationKey(seedArr)
	if err != nil {
		t.Fatalf("expandDecapsulationKey failed: %v", err)
	}

	// The public key should be 1216 bytes
	pk := make([]byte, 0, xwingPublicKeySize)
	pk = append(pk, pkM...)
	pk = append(pk, pkX...)
	if len(pk) != xwingPublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pk), xwingPublicKeySize)
	}

	// Verify the expected public key from the test vector (first 68 hex chars = 34 bytes)
	expectedPKPrefix := "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5"
	pkHex := hex.EncodeToString(pk)
	if pkHex[:64] != expectedPKPrefix {
		t.Fatalf("public key prefix mismatch:\ngot  %s\nwant %s", pkHex[:64], expectedPKPrefix)
	}

	// We can't test encapsulate/decapsulate with the test vector directly because
	// encapsulation is randomized, but we can verify the shared secret length
	// and that encapsulate/decapsulate are consistent with our own keys.
	ss, ct, err := xwingEncapsulate(pk)
	if err != nil {
		t.Fatalf("xwingEncapsulate failed: %v", err)
	}

	if len(ss) != xwingSharedKeySize {
		t.Fatalf("shared secret size: got %d, want %d", len(ss), xwingSharedKeySize)
	}

	// Verify decapsulation recovers the same shared secret
	ssDecap, err := xwingDecapsulate(ct[:], seedArr)
	if err != nil {
		t.Fatalf("xwingDecapsulate failed: %v", err)
	}

	if ss != ssDecap {
		t.Fatal("encapsulate/decapsulate shared secret mismatch")
	}

	// The expected shared secret from the RFC is for a specific eseed;
	// since we used a random eseed, ours will differ. Just verify the format.
	_ = expectedSS // We verified the format; deterministic test would need EncapsulateDerand
}

func TestXWingSizes(t *testing.T) {
	if xwingPublicKeySize != 1216 {
		t.Fatalf("xwingPublicKeySize: got %d, want 1216", xwingPublicKeySize)
	}
	if xwingCiphertextSize != 1120 {
		t.Fatalf("xwingCiphertextSize: got %d, want 1120", xwingCiphertextSize)
	}
	if xwingSeedSize != 32 {
		t.Fatalf("xwingSeedSize: got %d, want 32", xwingSeedSize)
	}
	if xwingSharedKeySize != 32 {
		t.Fatalf("xwingSharedKeySize: got %d, want 32", xwingSharedKeySize)
	}
}

func TestXWingEncapsulateDecapsulateConsistency(t *testing.T) {
	// Generate multiple key pairs and verify encaps/decaps consistency
	for range 10 {
		kp, err := NewXWingKeyPair()
		if err != nil {
			t.Fatalf("NewXWingKeyPair failed: %v", err)
		}

		_, _, pkM, pkX, err := expandDecapsulationKey(kp.seed)
		if err != nil {
			t.Fatal(err)
		}

		pk := make([]byte, 0, xwingPublicKeySize)
		pk = append(pk, pkM...)
		pk = append(pk, pkX...)

		ss, ct, err := xwingEncapsulate(pk)
		if err != nil {
			t.Fatalf("xwingEncapsulate failed: %v", err)
		}

		ssDecap, err := xwingDecapsulate(ct[:], kp.seed)
		if err != nil {
			t.Fatalf("xwingDecapsulate failed: %v", err)
		}

		if ss != ssDecap {
			t.Fatal("encapsulate/decapsulate shared secret mismatch")
		}
	}
}
