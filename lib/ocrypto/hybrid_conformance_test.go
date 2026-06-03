package ocrypto

import (
	"crypto/ecdh"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHybridOIDsMatchDrafts pins the AlgorithmIdentifier OIDs to the exact
// values registered by the IETF drafts. A mismatch here means we are
// advertising the wrong algorithm in SPKI/PKCS#8.
//
// Sources:
//   - draft-ietf-lamps-pq-composite-kem-14 §3 (id-MLKEM768-ECDH-P256, id-MLKEM1024-ECDH-P384)
//   - draft-connolly-cfrg-xwing-kem-10 §6 (id-Xwing)
func TestHybridOIDsMatchDrafts(t *testing.T) {
	assert.Equal(t,
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 59},
		oidCompositeMLKEM768P256,
		"P-256+ML-KEM-768 OID drift from draft-14")
	assert.Equal(t,
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 63},
		oidCompositeMLKEM1024P384,
		"P-384+ML-KEM-1024 OID drift from draft-14")
	assert.Equal(t,
		asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722},
		oidXWing,
		"X-Wing OID drift from draft-10")
}

// TestHybridCombinerLabelsMatchDraft pins the ASCII Label strings fed into the
// SHA3-256 combiner. The draft mandates these exact bytes; any drift would
// silently produce non-interop wrap keys.
//
// Source: draft-ietf-lamps-pq-composite-kem-14 §4.3, Table "Combiner Labels".
func TestHybridCombinerLabelsMatchDraft(t *testing.T) {
	assert.Equal(t, "MLKEM768-P256", labelMLKEM768P256)
	assert.Equal(t, "MLKEM1024-P384", labelMLKEM1024P384)
}

// TestP256MLKEM768PublicKeyConcatOrder verifies that the raw public-key
// material under our SPKI envelope is laid out as `mlkemPK || ecPoint`, in
// that order, per draft-14 §3.2 (the order was flipped from earlier internal
// versions).
func TestP256MLKEM768PublicKeyConcatOrder(t *testing.T) {
	kp, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, block)

	oid, raw, err := parseHybridSPKI(block.Bytes)
	require.NoError(t, err)
	require.True(t, oid.Equal(oidCompositeMLKEM768P256))
	require.Len(t, raw, P256MLKEM768PublicKeySize)

	// First P256MLKEM768MLKEMPubKeySize bytes are the ML-KEM-768 public key;
	// trailing P256MLKEM768ECPublicKeySize bytes are the uncompressed P-256
	// SEC1 point (leading 0x04 tag).
	ecPoint := raw[P256MLKEM768MLKEMPubKeySize:]
	require.Len(t, ecPoint, P256MLKEM768ECPublicKeySize)
	assert.Equal(t, byte(0x04), ecPoint[0], "EC half must be uncompressed SEC1 (0x04 tag)")

	// Round-trip the EC half through crypto/ecdh to prove it's a valid point.
	_, err = ecdh.P256().NewPublicKey(ecPoint)
	assert.NoError(t, err, "trailing bytes must parse as a P-256 ECDH public key")
}

// TestP384MLKEM1024PublicKeyConcatOrder mirrors the P-256 case for the larger
// scheme.
func TestP384MLKEM1024PublicKeyConcatOrder(t *testing.T) {
	kp, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, block)

	oid, raw, err := parseHybridSPKI(block.Bytes)
	require.NoError(t, err)
	require.True(t, oid.Equal(oidCompositeMLKEM1024P384))
	require.Len(t, raw, P384MLKEM1024PublicKeySize)

	ecPoint := raw[P384MLKEM1024MLKEMPubKeySize:]
	require.Len(t, ecPoint, P384MLKEM1024ECPublicKeySize)
	assert.Equal(t, byte(0x04), ecPoint[0], "EC half must be uncompressed SEC1 (0x04 tag)")
	_, err = ecdh.P384().NewPublicKey(ecPoint)
	assert.NoError(t, err, "trailing bytes must parse as a P-384 ECDH public key")
}

// TestHybridCrossSchemeDispatchRejection verifies that the dispatcher will not
// happily decrypt an X-Wing-wrapped DEK with a P-256+ML-KEM-768 private key
// (or any other mismatched pairing) — the OID inside the PKCS#8 envelope is
// the only thing routing the decryption path, and it must be authoritative.
func TestHybridCrossSchemeDispatchRejection(t *testing.T) {
	xw, err := NewXWingKeyPair()
	require.NoError(t, err)
	nist, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	xwPub, err := xw.PublicKeyInPemFormat()
	require.NoError(t, err)
	nistPriv, err := nist.PrivateKeyInPemFormat()
	require.NoError(t, err)

	xwEnc, err := FromPublicPEM(xwPub)
	require.NoError(t, err)
	wrapped, err := xwEnc.Encrypt([]byte("cross-scheme-dek"))
	require.NoError(t, err)

	nistDec, err := FromPrivatePEM(nistPriv)
	require.NoError(t, err)

	_, err = nistDec.Decrypt(wrapped)
	require.Error(t, err, "NIST decryptor must not accept an X-Wing wrapped envelope")
}
