package ocrypto

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeCompressedZeroSeed(l int) []byte {
	seed := make([]byte, l)
	seed[0] = 3
	return seed
}

func makeCompressedRandomSeed(f *testing.F, mode ECCMode) []byte {
	curve, err := GetECCurveFromECCMode(mode)
	require.NoError(f, err)
	keyPair, err := NewECKeyPair(mode)
	require.NoError(f, err)
	pubKey := keyPair.PrivateKey.PublicKey

	return elliptic.MarshalCompressed(curve, pubKey.X, pubKey.Y)
}

func FuzzUncompressECPubKey(f *testing.F) {
	// real random key examples
	f.Add(makeCompressedRandomSeed(f, ECCModeSecp256r1))
	f.Add(makeCompressedRandomSeed(f, ECCModeSecp384r1))
	f.Add(makeCompressedRandomSeed(f, ECCModeSecp521r1))
	// zero examples
	f.Add(makeCompressedZeroSeed(curveByteLength(elliptic.P224())))
	f.Add(makeCompressedZeroSeed(curveByteLength(elliptic.P256())))
	f.Add(makeCompressedZeroSeed(curveByteLength(elliptic.P384())))
	f.Add(makeCompressedZeroSeed(curveByteLength(elliptic.P521())))

	f.Fuzz(func(t *testing.T, data []byte) {
		curve := elliptic.P256()
		switch len(data) { // check if other curves are a better fit
		case curveByteLength(elliptic.P224()):
			curve = elliptic.P224()
		case curveByteLength(elliptic.P384()):
			curve = elliptic.P384()
		case curveByteLength(elliptic.P521()):
			curve = elliptic.P521()
		}

		require.NotPanics(t, func() {
			_, _ = UncompressECPubKey(curve, data)
		})
	})
}

func curveByteLength(curve elliptic.Curve) int {
	return 1 + (curve.Params().BitSize+7)/8
}
