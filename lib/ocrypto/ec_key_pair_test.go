package ocrypto

import (
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
