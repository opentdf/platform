package ocrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECKeyPair(t *testing.T) {
	for _, modeGood := range []ECCMode{ECCModeSecp256r1, ECCModeSecp384r1, ECCModeSecp521r1} {
		ecKeyPair, err := NewECKeyPair(modeGood)
		require.NoError(t, err, "fail on NewECKeyPair")

		_, err = ecKeyPair.PublicKeyInPemFormat()
		require.NoError(t, err, "fail on PublicKeyInPemFormat")

		_, err = ecKeyPair.PrivateKeyInPemFormat()
		require.NoError(t, err, "fail on PrivateKeyInPemFormat")

		keySize, err := ecKeyPair.KeySize()
		require.NoError(t, err, "fail on KeySize")

		// Set expected size based on mode
		var size int
		switch modeGood {
		case ECCModeSecp256r1:
			size = 256
		case ECCModeSecp384r1:
			size = 384
		case ECCModeSecp521r1:
			size = 521
		case ECCModeSecp256k1:
			fallthrough
		default:
			size = 99999 // deliberately bad value
		}

		assert.Equal(t, keySize, size, "invalid key size for mode %d", modeGood)
	}

	// Fail case
	emptyECKeyPair := ECKeyPair{}

	_, err := emptyECKeyPair.PrivateKeyInPemFormat()
	require.Error(t, err, "EcKeyPair.PrivateKeyInPemFormat() fail to return error")

	_, err = emptyECKeyPair.PublicKeyInPemFormat()
	require.Error(t, err, "EcKeyPair.PublicKeyInPemFormat() fail to return error")

	_, err = emptyECKeyPair.KeySize()
	require.Error(t, err, "EcKeyPair.keySize() fail to return error")

	for _, modeBad := range []ECCMode{ECCModeSecp256k1} {
		_, err := NewECKeyPair(modeBad)
		assert.Error(t, err, "did not fail as expected: NewECKeyPair(%d)", modeBad)
	}
}

func TestECRewrapKeyGenerate(t *testing.T) {
	// KAS key pair
	kasKey, err := NewECPrivateKey(ECCModeSecp256r1)
	require.NoError(t, err, "fail on NewECPrivateKey")

	kasPublicKey, err := kasKey.Public()
	require.NoError(t, err, "fail to get KAS public key")

	sampleKey := []byte("samplekey")
	wrappedKey, err := kasPublicKey.Encrypt(sampleKey)
	require.NoError(t, err, "fail unable to encypt samplekey")

	unwrappedKey, err := kasKey.DecryptWithEphemeralKey(wrappedKey, kasPublicKey.EphemeralKey())
	require.NoError(t, err, "fail to unwrap")

	assert.Equal(t, sampleKey, unwrappedKey)
}

func TestECDSASignature(t *testing.T) {
	digest := CalculateSHA256([]byte("Virtru"))
	for _, cvurve := range []ECCMode{ECCModeSecp256r1, ECCModeSecp384r1, ECCModeSecp521r1} {
		ecKeyPair, err := NewECKeyPair(cvurve)
		require.NoError(t, err, "fail on NewECKeyPair")

		rBytes, sBytes, err := ComputeECDSASig(digest, ecKeyPair.PrivateKey)
		require.NoError(t, err, "fail on ComputeECDSASig")

		verify := VerifyECDSASig(digest, rBytes, sBytes, &ecKeyPair.PrivateKey.PublicKey)
		if verify == false {
			t.Fatalf("Fail to verify ECDSA Signature")
		}
	}
}
