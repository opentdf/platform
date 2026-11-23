package ocrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECPublicKeyCompression(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		mode  ECCMode
	}{
		{elliptic.P224(), ECCModeSecp256k1}, // Decompression also supports P-224.
		{elliptic.P256(), ECCModeSecp256r1},
		{elliptic.P384(), ECCModeSecp384r1},
		{elliptic.P521(), ECCModeSecp521r1},
	} {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			for _, negateY := range []bool{false, true} {
				x, y := tc.curve.Params().Gx, tc.curve.Params().Gy
				if negateY {
					y = new(big.Int).Sub(tc.curve.Params().P, y)
				}
				coordinateHexSize := 2 * ((tc.curve.Params().BitSize + 7) / 8)
				uncompressed, err := hex.DecodeString(fmt.Sprintf("04%0*x%0*x", coordinateHexSize, x, coordinateHexSize, y))
				require.NoError(t, err)
				compressed := elliptic.MarshalCompressed(tc.curve, x, y)
				pub, err := UncompressECPubKey(tc.curve, compressed)
				require.NoError(t, err)
				encoded, err := pub.Bytes()
				require.NoError(t, err)
				require.Equal(t, uncompressed, encoded)

				if tc.curve != elliptic.P224() {
					encoded, err = CompressedECPublicKey(tc.mode, *pub)
					require.NoError(t, err)
					require.Equal(t, compressed, encoded)
				}
			}

			x, y := tc.curve.Params().Gx, tc.curve.Params().Gy
			compressed := elliptic.MarshalCompressed(tc.curve, x, y)
			invalidPoint := make([]byte, len(compressed))
			invalidPoint[0] = 2
			for i := 1; i < len(invalidPoint); i++ {
				invalidPoint[i] = 0xff // x is outside the curve's field.
			}
			for _, invalid := range [][]byte{nil, {0}, compressed[:len(compressed)-1], append([]byte{4}, compressed[1:]...), invalidPoint} {
				pub, err := UncompressECPubKey(tc.curve, invalid)
				require.Error(t, err)
				require.Nil(t, pub)
			}
		})
	}
}

func TestCompressedECPublicKeyInvalidKey(t *testing.T) {
	keyPair, err := NewECKeyPair(ECCModeSecp256r1)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		mode ECCMode
		pub  ecdsa.PublicKey
	}{
		{"unsupported mode", ECCModeSecp256k1, keyPair.PrivateKey.PublicKey},
		{"mismatched curve", ECCModeSecp384r1, keyPair.PrivateKey.PublicKey},
		{"unsupported key curve", ECCModeSecp256r1, ecdsa.PublicKey{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compressed, err := CompressedECPublicKey(tc.mode, tc.pub)
			require.Error(t, err)
			require.Nil(t, compressed)
		})
	}
}

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
