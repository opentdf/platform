package ocrypto

import (
	"crypto/sha256"
	"testing"

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

		if keySize != size {
			t.Fatalf("invalid key size for mode %d, expected:%d actual:%d",
				modeGood, size, keySize)
		}
	}

	// Fail case
	emptyECKeyPair := ECKeyPair{}

	_, err := emptyECKeyPair.PrivateKeyInPemFormat()
	if err == nil {
		t.Fatal("EcKeyPair.PrivateKeyInPemFormat() fail to return error")
	}

	_, err = emptyECKeyPair.PublicKeyInPemFormat()
	if err == nil {
		t.Fatal("EcKeyPair.PublicKeyInPemFormat() fail to return error")
	}

	_, err = emptyECKeyPair.KeySize()
	if err == nil {
		t.Fatal("EcKeyPair.keySize() fail to return error")
	}

	for _, modeBad := range []ECCMode{ECCModeSecp256k1} {
		_, err := NewECKeyPair(modeBad)
		if err == nil {
			t.Fatalf("did not fail as expected: NewECKeyPair(%d): %v", modeBad, err)
		}
	}
}

func TestECRewrapKeyGenerate(t *testing.T) {
	kasECKeyPair, err := NewECKeyPair(ECCModeSecp256r1)
	require.NoError(t, err, "fail on NewECKeyPair")

	kasPubKeyAsPem, err := kasECKeyPair.PublicKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec public key in pem format")

	kasPrivateKeyAsPem, err := kasECKeyPair.PrivateKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec private key in pem format")

	sdkECKeyPair, err := NewECKeyPair(ECCModeSecp256r1)
	require.NoError(t, err, "fail on NewECKeyPair")

	sdkPubKeyAsPem, err := sdkECKeyPair.PublicKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec public key in pem format")

	sdkPrivateKeyAsPem, err := sdkECKeyPair.PrivateKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec private key in pem format")

	kasECDHKey, err := ComputeECDHKey([]byte(kasPrivateKeyAsPem), []byte(sdkPubKeyAsPem))
	require.NoError(t, err, "fail to calculate ecdh key")

	// slat
	digest := sha256.New()
	digest.Write([]byte("TDF"))

	kasSymmetricKey, err := CalculateHKDF(digest.Sum(nil), kasECDHKey)
	require.NoError(t, err, "fail to calculate HKDF key")

	sdkECDHKey, err := ComputeECDHKey([]byte(sdkPrivateKeyAsPem), []byte(kasPubKeyAsPem))
	require.NoError(t, err, "fail to calculate ecdh key")

	sdkSymmetricKey, err := CalculateHKDF(digest.Sum(nil), sdkECDHKey)
	require.NoError(t, err, "fail to calculate HKDF key")

	if string(kasSymmetricKey) != string(sdkSymmetricKey) {
		t.Fatalf("symmetric keys on both kas and sdk should be same kas:%s sdk:%s",
			string(kasSymmetricKey), string(sdkSymmetricKey))
	}
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
