package ocrypto

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hexBytes decodes a hex string in a KAT vector. Tests fail fatally on bad
// hex — these are spec-pinned constants, not user input.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestHybridOIDsMatchDrafts pins the AlgorithmIdentifier OIDs to the exact
// values registered by the IETF drafts. A mismatch here means we are
// advertising the wrong algorithm in SPKI/PKCS#8.
//
// Sources:
//   - draft-ietf-lamps-pq-composite-kem-14 §6 (id-MLKEM768-ECDH-P256, id-MLKEM1024-ECDH-P384)
//   - draft-connolly-cfrg-xwing-kem-10 §5.8 (id-XWing)
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
// Source: draft-ietf-lamps-pq-composite-kem-14 §6 ("ParameterSet" Label column).
func TestHybridCombinerLabelsMatchDraft(t *testing.T) {
	assert.Equal(t, "MLKEM768-P256", labelMLKEM768P256)
	assert.Equal(t, "MLKEM1024-P384", labelMLKEM1024P384)
}

// TestP256MLKEM768PublicKeyConcatOrder verifies that the raw public-key
// material under our SPKI envelope is laid out as `mlkemPK || ecPoint`, in
// that order, per draft-14 §4.1 (SerializePublicKey).
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

func TestHybridNISTPrivateKeyAndCiphertextConcatOrder(t *testing.T) {
	tests := []struct {
		name           string
		newKeyPair     func(t *testing.T) HybridNISTKeyPair
		params         *hybridNISTParams
		privateSize    int
		ciphertextSize int
	}{
		{
			name:           "P256_MLKEM768",
			newKeyPair:     mustNewP256MLKEM768KeyPair,
			params:         &p256mlkem768Params,
			privateSize:    P256MLKEM768MLKEMSeedSize,
			ciphertextSize: P256MLKEM768MLKEMCtSize,
		},
		{
			name:           "P384_MLKEM1024",
			newKeyPair:     mustNewP384MLKEM1024KeyPair,
			params:         &p384mlkem1024Params,
			privateSize:    P384MLKEM1024MLKEMSeedSize,
			ciphertextSize: P384MLKEM1024MLKEMCtSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair := tt.newKeyPair(t)
			assertHybridNISTPrivateKeyLayout(t, keyPair, tt.params, tt.privateSize)
			assertHybridNISTWrappedCiphertextLayout(t, keyPair, tt.params, tt.ciphertextSize)
		})
	}
}

func mustNewP256MLKEM768KeyPair(t *testing.T) HybridNISTKeyPair {
	t.Helper()
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)
	return keyPair
}

func mustNewP384MLKEM1024KeyPair(t *testing.T) HybridNISTKeyPair {
	t.Helper()
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)
	return keyPair
}

func assertHybridNISTPrivateKeyLayout(t *testing.T, keyPair HybridNISTKeyPair, params *hybridNISTParams, mlkemSeedSize int) {
	t.Helper()

	privPEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(privPEM))
	require.NotNil(t, block)

	oid, raw, err := parseHybridPKCS8(block.Bytes)
	require.NoError(t, err)
	require.True(t, oid.Equal(params.oid))
	require.Greater(t, len(raw), mlkemSeedSize)
	require.Len(t, raw[:mlkemSeedSize], mlkemSeedSize)

	ecPrivDER := raw[mlkemSeedSize:]
	ecPriv, err := x509.ParseECPrivateKey(ecPrivDER)
	require.NoError(t, err, "tail must parse as ECPrivateKey DER")
	require.Same(t, params.namedCurve, ecPriv.Curve)
	ecdhPriv, err := ecPriv.ECDH()
	require.NoError(t, err)
	require.Len(t, ecdhPriv.PublicKey().Bytes(), params.ecPubSize)
}

func assertHybridNISTWrappedCiphertextLayout(t *testing.T, keyPair HybridNISTKeyPair, params *hybridNISTParams, mlkemCiphertextSize int) {
	t.Helper()

	enc, err := NewP256MLKEM768Encryptor(keyPair.publicKey)
	if params.keyType == HybridSecp384r1MLKEM1024Key {
		enc, err = NewP384MLKEM1024Encryptor(keyPair.publicKey)
	}
	require.NoError(t, err)

	wrappedDER, err := enc.Encrypt([]byte("layout-test-dek"))
	require.NoError(t, err)

	var wrapped HybridNISTWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrapped)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Len(t, wrapped.HybridCiphertext, mlkemCiphertextSize+params.ecPubSize)
	require.Len(t, wrapped.HybridCiphertext[:mlkemCiphertextSize], mlkemCiphertextSize)

	ephemeralECPub := wrapped.HybridCiphertext[mlkemCiphertextSize:]
	require.Len(t, ephemeralECPub, params.ecPubSize)
	require.Equal(t, byte(0x04), ephemeralECPub[0], "ephemeral EC point must be uncompressed SEC1")
	_, err = params.curve.NewPublicKey(ephemeralECPub)
	require.NoError(t, err, "tail must parse as ephemeral EC public key")
}

// TestHybridCrossSchemeDispatchRejection verifies that across all six
// (encrypt-scheme, decrypt-scheme) cross-pairings of the three hybrid
// schemes, the decrypter rejects a ciphertext produced by a different
// scheme. The OID embedded in the PKCS#8 envelope authoritatively routes
// the decryption path; a wrap produced by a different scheme MUST NOT
// decapsulate cleanly.
func TestHybridCrossSchemeDispatchRejection(t *testing.T) {
	schemes := []KeyType{HybridXWingKey, HybridSecp256r1MLKEM768Key, HybridSecp384r1MLKEM1024Key}
	for _, enc := range schemes {
		for _, dec := range schemes {
			if enc == dec {
				continue
			}
			t.Run(string(enc)+"_to_"+string(dec), func(t *testing.T) {
				encKP, err := NewHybridKeyPair(enc)
				require.NoError(t, err)
				decKP, err := NewHybridKeyPair(dec)
				require.NoError(t, err)

				encPub, err := encKP.PublicKeyInPemFormat()
				require.NoError(t, err)
				decPriv, err := decKP.PrivateKeyInPemFormat()
				require.NoError(t, err)

				encryptor, err := FromPublicPEM(encPub)
				require.NoError(t, err)
				wrapped, err := encryptor.Encrypt([]byte("cross-scheme-dek"))
				require.NoError(t, err)

				decryptor, err := FromPrivatePEM(decPriv)
				require.NoError(t, err)

				_, err = decryptor.Decrypt(wrapped)
				require.Error(t, err, "%s decryptor must not accept a %s wrapped envelope", dec, enc)
			})
		}
	}
}

// TestHybridCertificatePEMRejected verifies that a hybrid SPKI wrapped in a
// CERTIFICATE PEM block surfaces a clear "not supported" error from both
// dispatchers, rather than a confusing x509 parse error. Defense against
// operators pasting in a cert by mistake.
func TestHybridCertificatePEMRejected(t *testing.T) {
	kp, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)
	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, block)

	fakeCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})

	_, err = FromPublicPEM(string(fakeCert))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate-wrapped hybrid keys are not supported")

	_, err = FromPrivatePEM(string(fakeCert))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate-wrapped hybrid keys are not supported")
}

// TestHybridSPKIRejectsAlgorithmParameters verifies that any non-absent
// AlgorithmIdentifier `parameters` field on the hybrid SPKI/PKCS#8 envelope
// is rejected. Draft-14 §6 and draft-10 §5.8 both mandate parameters be
// absent for these schemes; carrying an explicit NULL would still violate.
func TestHybridSPKIRejectsAlgorithmParameters(t *testing.T) {
	type algIDWithParams struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	type spkiWithParams struct {
		Algorithm        algIDWithParams
		SubjectPublicKey asn1.BitString
	}
	bogus := spkiWithParams{
		Algorithm: algIDWithParams{
			Algorithm:  oidCompositeMLKEM768P256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull, Bytes: []byte{}},
		},
		SubjectPublicKey: asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}
	der, err := asn1.Marshal(bogus)
	require.NoError(t, err)

	_, _, err = parseHybridSPKI(der)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parameters must be absent")
}

// TestCombinerKAT_MLKEM768_ECDH_P256 verifies hybridNISTCombiner byte-for-byte
// against the IETF-supplied combiner vector from lamps-wg/draft-composite-kem
// src/kemCombiner_MLKEM768_ECDH_P256_SHA3_256.md. Confirms that our SHA3-256
// input ordering and Label encoding match the draft-14 §3.4 specification.
//
// Source: https://github.com/lamps-wg/draft-composite-kem/blob/main/src/kemCombiner_MLKEM768_ECDH_P256_SHA3_256.md
func TestCombinerKAT_MLKEM768_ECDH_P256(t *testing.T) {
	mlkemSS := hexBytes(t, "ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43")
	tradSS := hexBytes(t, "ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0")
	tradCT := hexBytes(t,
		"041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d19171270cdefcd4"+
			"abb682edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5e7610")
	tradPK := hexBytes(t,
		"04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159ff73d38d2"+
			"9aa94f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e80396a3e")
	expectedSS := hexBytes(t, "d6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee")

	got := hybridNISTCombiner(&p256mlkem768Params, mlkemSS, tradSS, tradCT, tradPK)
	assert.Equal(t, expectedSS, got, "combiner output diverged from draft-14 §3.4 KAT")
}

// TestCombinerKAT_MLKEM1024_ECDH_P384 mirrors the above for the P-384 variant.
//
// Source: https://github.com/lamps-wg/draft-composite-kem/blob/main/src/kemCombiner_MLKEM1024_ECDH_P384_SHA3_256.md
func TestCombinerKAT_MLKEM1024_ECDH_P384(t *testing.T) {
	mlkemSS := hexBytes(t, "c0f87f0c53fa8e2ba192a494694d37d1e3cf99c65e0dc5f69b2cc044b3fb205d")
	tradSS := hexBytes(t,
		"4d52b7ef430382f479603207c0b8f7aa5bc35d8758835007e39a2642ad65e635"+
			"d674db7a5513889657fb24e4e228a098")
	tradCT := hexBytes(t,
		"0401a5b81dcb51290a0eb142b9032d5a37503164b7a20ac0e3b52dc54f9b0b7c9f"+
			"dd2699a59563a0b9ad0e54478846faeab72b92275e1fbb8b963bcc6e80e30c089"+
			"fbe4ed8d47ec76951db94aede46e679d5692eeb1d1b150d5b2e6660dc67c469")
	tradPK := hexBytes(t,
		"0468cc4acc5dd85edbcbf25bae7ee7dcacec2968ea7ee57fc91311cb9c47d4a24c"+
			"3854e5ce3e5d0b309fda493224520f2870496eb16571108b3deafd72c1df17edc"+
			"302fbb8b60bae44d93177e6df5278e4667a090a2d59a2076f41d693975e8d19")
	expectedSS := hexBytes(t, "eb60f6c80a309ad4158d7b02f2cf8c947faead96ebbd85c3f62a94868ffddca4")

	got := hybridNISTCombiner(&p384mlkem1024Params, mlkemSS, tradSS, tradCT, tradPK)
	assert.Equal(t, expectedSS, got, "combiner output diverged from draft-14 §3.4 KAT")
}

// TestCombinerLabelEncodingKAT pins the ASCII Label byte encoding to the
// draft's hex form. A drift here means our domain separator is wrong and
// would produce non-interop wrap keys.
//
// Sources: draft-ietf-lamps-pq-composite-kem-14 §6, vectors above.
func TestCombinerLabelEncodingKAT(t *testing.T) {
	assert.Equal(t, hexBytes(t, "4d4c4b454d3736382d50323536"), []byte(labelMLKEM768P256))
	assert.Equal(t, hexBytes(t, "4d4c4b454d313032342d50333834"), []byte(labelMLKEM1024P384))
}
